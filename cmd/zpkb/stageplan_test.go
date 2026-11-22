package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const stageDist = "oci://example.test/pkgs"

// stageTarball is a real, tiny tar.gz, distinct per project.
func stageTarball(t *testing.T, project string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	body := []byte("payload of " + project)
	if err := tw.WriteHeader(&tar.Header{Name: "bin/tool", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// stageRig drives the REAL publishArtifact with only the registry stubbed, so
// what a run pushed can be compared byte for byte between the two paths.
type stageRig struct {
	h      *factoryHarness
	pushes []string
	key    string // path of a secret key file
}

func newStageRig(t *testing.T) *stageRig {
	t.Helper()
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	r := &stageRig{h: h}
	factoryBuild = func(_ *build.Runner, p build.Plan, _ *pantry.Recipe, project string, _, _ target.Target, out string) (build.Result, error) {
		h.built = append(h.built, project+"@="+p.Version)
		path := filepath.Join(out, project, "v"+p.Version+".tar.gz")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, stageTarball(t, project+p.Version), 0o644); err != nil {
			t.Fatal(err)
		}
		return build.Result{
			Version: p.Version, Concrete: p.Concrete, SpecHash: p.SpecHash, ArtifactPath: path,
			Source: build.SourceRef{
				URI: "https://example.test/" + project + ".tgz", SHA256: strings.Repeat("ab", 32),
				Extra: []build.SourceRef{{URI: "https://example.test/extra.tgz", SHA256: strings.Repeat("cd", 32)}},
			},
			BuildEnv: []moustache.Dep{{Project: "gnu.org/gcc", Version: "14.2.0", Path: "/opt/gcc"}},
		}, nil
	}
	factoryPublish = publishArtifact
	oldDigest, oldPush := ociArtifactDigest, ociPush
	t.Cleanup(func() { ociArtifactDigest, ociPush = oldDigest, oldPush })
	ociArtifactDigest = func(_, _, _, _, _ string) (string, error) { return "", nil }
	ociPush = func(dist, project, tag, osn, arch string, tarball []byte, ext string, refs []artifact.Referrer, ann map[string]string) (ocispec.Descriptor, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s|%s|%x|%v", dist, project, tag, osn, arch, ext, tarball, ann)
		for _, ref := range refs {
			fmt.Fprintf(&b, "|%s %s %s %v", ref.ArtifactType, ref.MediaType, ref.Blob, ref.Annotations)
		}
		r.pushes = append(r.pushes, b.String())
		return ocispec.Descriptor{Digest: digest.FromString(project + tag + arch)}, nil
	}
	withEnsurer(t, &fakeEnsurer{}, nil)
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	r.key = filepath.Join(t.TempDir(), "k.sec")
	if err := os.WriteFile(r.key, []byte(kp.SecretKeyFile("test")), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// stage runs the build half and returns the plan path.
func (r *stageRig) stage(t *testing.T) string {
	t.Helper()
	if code := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist); code != 0 {
		t.Fatalf("stage-only: code=%d\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
	}
	if len(r.pushes) != 0 {
		t.Fatalf("--stage-only pushed: %v", r.pushes)
	}
	return filepath.Join(r.h.artifacts, stagePlanName)
}

func (r *stageRig) publishStage(extra ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runPublishStage(append([]string{r.h.artifacts}, extra...), &out, &errb)
	return code, out.String(), errb.String()
}

// firstDiff names where two long strings part, with a little context, so a
// failure is readable instead of two screens of attestation JSON.
func firstDiff(want, got string) string {
	i := 0
	for i < len(want) && i < len(got) && want[i] == got[i] {
		i++
	}
	cut := func(s string) string {
		lo, hi := max(i-60, 0), min(i+60, len(s))
		return s[lo:hi]
	}
	return fmt.Sprintf("first difference at byte %d\n  factory --to:  %q\n  publish-stage: %q", i, cut(want), cut(got))
}

// okLines is what a run says about each artifact, with the summary dropped
// (the two summaries rightly differ).
func okLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "✅ OK") || strings.Contains(l, "PUSHED") || strings.Contains(l, "pushed") {
			out = append(out, l)
		}
	}
	return out
}

// ⛔⛔ THE SPLIT MUST BE INVISIBLE TO THE REGISTRY. `factory --to` and
// `factory --stage-only` + `publish-stage --to` have to push the same bytes under
// the same tags with the same attestations, signed by the same key: a split that
// changed what is published would be a different product, not a hardening.
func TestPublishStageEqualsFactoryTo(t *testing.T) {
	// A: the single-process path, the control.
	a := newStageRig(t)
	if code := a.h.run(t, "--sign", a.key, "--recipes", "app.org", "--max-versions", "1", "--to", stageDist); code != 0 {
		t.Fatalf("factory --to: code=%d\n%s\n%s", code, a.h.out.String(), a.h.errb.String())
	}
	if len(a.pushes) < 2 {
		t.Fatalf("the control pushed %d artifact(s); the comparison would prove nothing", len(a.pushes))
	}
	aOut := okLines(a.h.out.String())

	// B: build with no key, publish from the plan.
	b := newStageRig(t)
	b.key = a.key // the same key, or the signatures would differ for the right reason
	b.stage(t)
	code, out, errb := b.publishStage("--to", stageDist, "--sign", b.key)
	if code != 0 {
		t.Fatalf("publish-stage: code=%d\n%s\n%s", code, out, errb)
	}
	if got, want := strings.Join(b.pushes, "\n"), strings.Join(a.pushes, "\n"); got != want {
		t.Fatalf("publish-stage pushed something different from factory --to: %s", firstDiff(want, got))
	}
	if got, want := strings.Join(okLines(out), "\n"), strings.Join(aOut, "\n"); got != want {
		t.Fatalf("the two paths say different things: %s", firstDiff(want, got))
	}
	// The signature is in the pushes of BOTH, so equality above is not two
	// unsigned runs agreeing.
	if !strings.Contains(a.pushes[0], artifact.ArtifactTypeSignature) {
		t.Fatalf("the control is unsigned:\n%s", a.pushes[0])
	}
}

func TestStageOnlyRefusesWhatWouldHandItTheKeys(t *testing.T) {
	for _, c := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"--sign", "", []string{"--sign", "k.sec"}, "sign"},
		{"$SIGNING_KEY", "AAAA", nil, "SIGNING_KEY"},
		{"--mirror-from", "", []string{"--mirror-from", "https://dist.pkgx.dev"}, "mirror"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newStageRig(t)
			t.Setenv("SIGNING_KEY", c.env)
			code := r.h.run(t, append([]string{"--stage-only", "--recipes", "lib.org", "--to", stageDist}, c.args...)...)
			if code != 2 {
				t.Fatalf("code=%d, want a usage refusal\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
			}
			if !strings.Contains(r.h.errb.String(), c.want) {
				t.Errorf("the refusal does not name %q:\n%s", c.want, r.h.errb.String())
			}
			if len(r.h.built) != 0 {
				t.Errorf("built %v before refusing", r.h.built)
			}
		})
	}
}

func TestStageOnlyBuildsStagesAndSaysSigningIsDeferred(t *testing.T) {
	r := newStageRig(t)
	plan := r.stage(t)
	out := r.h.out.String()
	for _, want := range []string{"deferred", "--stage-only", "stage plan: 2 artifact(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseStagePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Dist != stageDist || p.Platform != "linux/x86-64" || len(p.Artifacts) != 2 {
		t.Fatalf("plan = %+v", p)
	}
	for _, e := range p.Artifacts {
		if e.Spec == "" || !strings.Contains(e.Tag, "-h") {
			t.Errorf("entry carries no build identity: %+v", e)
		}
	}
}

// ⛔ A PLAN IS INPUT FROM THE SIDE THAT RAN THIRD-PARTY CODE. Every one of these
// is a stage a hostile or broken build could leave, and each must be refused
// WHOLE: nothing pushed, not the artifacts before the bad one.
func TestPublishStageRefusesATamperedStage(t *testing.T) {
	type edit func(t *testing.T, r *stageRig, p *stagePlan)
	file0 := func(r *stageRig, p *stagePlan) string {
		return filepath.Join(r.h.artifacts, filepath.FromSlash(p.Artifacts[1].File))
	}
	for _, c := range []struct {
		name string
		args []string // overrides the default --to/--sign
		edit edit
		want string
	}{
		{"wrong destination", []string{"--to", "oci://elsewhere.test/pkgs"}, nil, "not oci://elsewhere"},
		{"same-size tamper", nil, func(t *testing.T, r *stageRig, p *stagePlan) {
			b, _ := os.ReadFile(file0(r, p))
			b[len(b)-1] ^= 0xff
			if err := os.WriteFile(file0(r, p), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "sha256"},
		{"truncated", nil, func(t *testing.T, r *stageRig, p *stagePlan) {
			b, _ := os.ReadFile(file0(r, p))
			if err := os.WriteFile(file0(r, p), b[:len(b)-1], 0o644); err != nil {
				t.Fatal(err)
			}
		}, "bytes"},
		{"parent path", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].File = "../x.tar.gz" }, "clean relative path"},
		{"absolute path", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].File = "/etc/passwd.tar.gz" }, "clean relative path"},
		{"not an archive", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].File = stagePlanName }, "plan itself"},
		{"symlink out of the stage", nil, func(t *testing.T, r *stageRig, p *stagePlan) {
			outside := filepath.Join(t.TempDir(), "outside.tar.gz")
			if err := os.WriteFile(outside, stageTarball(t, "evil"), 0o644); err != nil {
				t.Fatal(err)
			}
			sum, size, _ := hashFile(outside)
			p.Artifacts[1].SHA256, p.Artifacts[1].Size = sum, size // the plan AGREES with the file
			if err := os.Remove(file0(r, p)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, file0(r, p)); err != nil {
				t.Skip("symlinks unavailable:", err)
			}
		}, "escapes"},
		{"tag that its spec does not give", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].Tag = "9.9.9" }, "tag"},
		{"spec not canonical", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].Spec += " " }, "spec"},
		{"duplicate entry", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts = append(p.Artifacts, p.Artifacts[0]) }, "twice"},
		{"other platform", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].Arch = "aarch64" }, "platform"},
		{"bad digest", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].SHA256 = "XYZ" }, "sha256"},
		{"control character", nil, func(t *testing.T, r *stageRig, p *stagePlan) { p.Artifacts[1].Source.URI = "a\x1b[2Jb" }, "control"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newStageRig(t)
			planPath := r.stage(t)
			data, err := os.ReadFile(planPath)
			if err != nil {
				t.Fatal(err)
			}
			var p stagePlan
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			if c.edit != nil {
				c.edit(t, r, &p)
				raw, err := json.Marshal(&p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(planPath, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := c.args
			if args == nil {
				args = []string{"--to", stageDist}
			}
			code, out, errb := r.publishStage(append(args, "--sign", r.key)...)
			if code == 0 {
				t.Fatalf("a tampered stage was published:\n%s", out)
			}
			if len(r.pushes) != 0 {
				t.Fatalf("pushed %d artifact(s) from a stage it should have refused whole", len(r.pushes))
			}
			if !strings.Contains(errb, c.want) {
				t.Errorf("the refusal does not mention %q:\n%s", c.want, errb)
			}
		})
	}
}

func TestPublishStageNeedsADestinationAndAKey(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	t.Setenv("DIST", stageDist) // an environment default must NOT stand in for --to
	if code, _, errb := r.publishStage(); code != 2 || !strings.Contains(errb, "usage") {
		t.Fatalf("no --to: code=%d %s", code, errb)
	}
	if code, _, errb := r.publishStage("--to", stageDist); code != 2 || !strings.Contains(errb, "signing key") {
		t.Fatalf("no key: code=%d %s", code, errb)
	}
	if code, _, errb := r.publishStage("--to", "https://example.test"); code != 2 || !strings.Contains(errb, "oci://") {
		t.Fatalf("not oci: code=%d %s", code, errb)
	}
	if len(r.pushes) != 0 {
		t.Fatalf("pushed anyway: %v", r.pushes)
	}
	if code, _, errb := r.publishStage("--to", stageDist, "--allow-unsigned"); code != 0 {
		t.Fatalf("--allow-unsigned: code=%d %s", code, errb)
	}
	if len(r.pushes) != 2 {
		t.Fatalf("pushes = %d, want 2", len(r.pushes))
	}
}

func TestStagePlanIsExtendedAcrossRunsAndNeverClobbered(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	// A second run into the same stage keeps what the first staged, and a
	// rebuilt artifact REPLACES its entry rather than listing it twice.
	if code := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--force", "--to", stageDist); code != 0 {
		t.Fatalf("second run: code=%d\n%s", code, r.h.errb.String())
	}
	data, _ := os.ReadFile(filepath.Join(r.h.artifacts, stagePlanName))
	p, err := parseStagePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want the first run's two kept without a duplicate", len(p.Artifacts))
	}
	// A plan it cannot read is refused, never replaced.
	if err := os.WriteFile(filepath.Join(r.h.artifacts, stagePlanName), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist); code == 0 {
		t.Fatal("overwrote a plan it could not read")
	}
	if b, _ := os.ReadFile(filepath.Join(r.h.artifacts, stagePlanName)); string(b) != "{broken" {
		t.Fatalf("the unreadable plan was replaced with %q", b)
	}
}

func TestParseStagePlanBounds(t *testing.T) {
	if _, err := parseStagePlan(bytes.Repeat([]byte(" "), maxStagePlanBytes+1)); err == nil {
		t.Error("an oversize plan was accepted")
	}
	for name, doc := range map[string]string{
		"unknown field": `{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[],"extra":1}`,
		"trailing data": `{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[]} {}`,
		"wrong schema":  `{"schema":2,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[]}`,
		"not oci":       `{"schema":1,"dist":"https://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[]}`,
		"time":          `{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":-1,"artifacts":[]}`,
	} {
		if _, err := parseStagePlan([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseStagePlan([]byte(`{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[]}`)); err != nil {
		t.Errorf("an empty plan is valid: %v", err)
	}
}

// FuzzParseStagePlan: whatever bytes arrive, a plan that is ACCEPTED has only
// clean relative files, hex digests and tags its own spec gives.
func FuzzParseStagePlan(f *testing.F) {
	f.Add([]byte(`{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[]}`))
	f.Add([]byte(`{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[{"project":"a.org","version":"1.0","tag":"1.0","os":"linux","arch":"x86-64","file":"a.org/v1.0.tar.gz","sha256":"` + strings.Repeat("0", 64) + `","size":1,"glibc":"","spec":"","source":{"uri":"","sha256":"","commit":""},"build_env":[],"bootstrap":""}]}`))
	f.Add([]byte(`{"schema":1,"dist":"oci://x/y","platform":"linux/x86-64","builder":"b","time":0,"artifacts":[{"file":"../x"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseStagePlan(data)
		if err != nil {
			return
		}
		for _, e := range p.Artifacts {
			if e.File == "" || filepath.IsAbs(e.File) || strings.Contains(e.File, "..") || strings.Contains(e.File, `\`) {
				t.Fatalf("accepted file %q", e.File)
			}
			if !reStageHex.MatchString(e.SHA256) {
				t.Fatalf("accepted digest %q", e.SHA256)
			}
			c, err := e.concrete()
			if err != nil || buildTag(e.Project, e.Version, e.Glibc, c) != e.Tag {
				t.Fatalf("accepted tag %q for %+v", e.Tag, e)
			}
		}
	})
}
