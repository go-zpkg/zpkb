package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Every guard of the plan parser is held here from BOTH sides: a value one past
// the limit is refused and the limit itself is accepted. The documents go
// through parseStagePlan directly, because through publish-stage a second check
// (the file's digest, its size) would refuse most of them for another reason
// and hide a guard that had been deleted.

func guardEntry(project, version string, n int) stageEntry {
	return stageEntry{
		Project: project, Version: version,
		Tag: buildTag(project, version, "", artifact.Concrete{}),
		OS:  "linux", Arch: "x86-64",
		File:   fmt.Sprintf("p%d/v.tar.gz", n),
		SHA256: strings.Repeat("0", 64), Size: 1, BuildEnv: []stageDep{},
	}
}

func guardPlan(es ...stageEntry) stagePlan {
	return stagePlan{Schema: stagePlanSchema, Dist: "oci://x/y", Platform: "linux/x86-64", Builder: "b", Artifacts: es}
}

func guardParse(t *testing.T, p stagePlan) error {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseStagePlan(b)
	return err
}

func TestStagePlanParserHoldsEveryBoundFromBothSides(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	with := func(f func(e *stageEntry)) stagePlan {
		e := guardEntry("a.org", "1.0", 0)
		f(&e)
		return guardPlan(e)
	}
	bad := func(project, version string) stageEntry {
		e := guardEntry(project, version, 0)
		return e
	}
	for _, c := range []struct {
		name string
		plan stagePlan
		want string // "" = accepted
	}{
		{"a valid entry", guardPlan(guardEntry("a.org", "1.0", 0)), ""},
		{"project at its limit", guardPlan(bad(long(200), "1.0")), ""},
		{"project one past its limit", guardPlan(bad(long(201), "1.0")), "limit"},
		{"uppercase project", guardPlan(bad("A.org", "1.0")), "bad project"},
		{"dotdot in a project", guardPlan(bad("a..b", "1.0")), "bad project"},
		{"version that starts with a dash", guardPlan(bad("a.org", "-1")), "bad version"},
		{"glibc that is not a number", with(func(e *stageEntry) { e.Glibc = "x" }), "bad glibc"},
		{"os with a space", with(func(e *stageEntry) { e.OS = "li nux" }), "bad os"},
		{"arch with a space", with(func(e *stageEntry) { e.Arch = "x 86" }), "bad arch"},
		{"entry digest not hex", with(func(e *stageEntry) { e.SHA256 = strings.Repeat("g", 64) }), "sha256"},
		{"entry digest short", with(func(e *stageEntry) { e.SHA256 = "ab" }), "sha256"},
		{"size at its limit", with(func(e *stageEntry) { e.Size = maxStageArtifact }), ""},
		{"size one past its limit", with(func(e *stageEntry) { e.Size = maxStageArtifact + 1 }), "size"},
		{"negative size", with(func(e *stageEntry) { e.Size = -1 }), "size"},
		{"file with a control character", with(func(e *stageEntry) { e.File = "a\x01.tar.gz" }), "control"},
		{"spec with a control character", with(func(e *stageEntry) { e.Spec = "a\x01" }), "control"},
		{"spec that does not parse", with(func(e *stageEntry) { e.Spec = "garbage" }), "spec"},
		{"source digest not hex", with(func(e *stageEntry) { e.Source.SHA256 = "zz" }), "sha256"},
		{"source digest hex", with(func(e *stageEntry) { e.Source.SHA256 = strings.Repeat("ab", 32) }), ""},
		{"source uri with a control character", with(func(e *stageEntry) { e.Source.URI = "a\x1bb" }), "control"},
		{"nested extra sources", with(func(e *stageEntry) {
			e.Source.Extra = []stageSource{{Extra: []stageSource{{}}}}
		}), "nested"},
		{"extra source with a control character", with(func(e *stageEntry) {
			e.Source.Extra = []stageSource{{URI: "a\x01"}}
		}), "extra[0]"},
		{"extras at their limit", with(func(e *stageEntry) { e.Source.Extra = make([]stageSource, maxStageExtras) }), ""},
		{"extras one past their limit", with(func(e *stageEntry) { e.Source.Extra = make([]stageSource, maxStageExtras+1) }), "extra sources"},
		{"build_env at its limit", with(func(e *stageEntry) { e.BuildEnv = make([]stageDep, maxStageEnv) }), ""},
		{"build_env one past its limit", with(func(e *stageEntry) { e.BuildEnv = make([]stageDep, maxStageEnv+1) }), "build_env entries"},
		{"build_env with a control character", with(func(e *stageEntry) {
			e.BuildEnv = []stageDep{{Path: "a\x01"}}
		}), "build_env[0]"},
		{"bootstrap that is not 0 or 1", with(func(e *stageEntry) { e.Bootstrap = "2" }), "bootstrap"},
		{"sovereign that is not 0 or 1", with(func(e *stageEntry) { e.Sovereign = "yes" }), "sovereign"},
		{"sovereign 1", with(func(e *stageEntry) { e.Sovereign = "1" }), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := guardParse(t, c.plan)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Fatal("accepted")
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("refused for another reason than %q: %v", c.want, err)
			}
		})
	}
}

func TestStagePlanHeaderGuards(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(p *stagePlan)
		want string
	}{
		{"dist with a control character", func(p *stagePlan) { p.Dist = "oci://x\x01y" }, "plan dist"},
		{"builder with a control character", func(p *stagePlan) { p.Builder = "b\x01" }, "plan builder"},
		{"platform with a control character", func(p *stagePlan) { p.Platform = "linux/x86\x01" }, "plan platform"},
		{"platform that is not os/arch", func(p *stagePlan) { p.Platform = "linuxx86" }, "bad platform"},
		{"time past 2100", func(p *stagePlan) { p.Time = maxStageTime + 1 }, "time"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := guardPlan()
			c.edit(&p)
			err := guardParse(t, p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, c.want)
			}
		})
	}
	p := guardPlan()
	p.Time = maxStageTime
	if err := guardParse(t, p); err != nil {
		t.Errorf("time at its limit: %v", err)
	}
}

func TestStagePlanEntryCountAndSizeLimits(t *testing.T) {
	many := func(n int) stagePlan {
		es := make([]stageEntry, n)
		for i := range es {
			es[i] = guardEntry("a.org", fmt.Sprintf("1.%d", i), i)
		}
		return guardPlan(es...)
	}
	if err := guardParse(t, many(maxStageEntries)); err != nil {
		t.Fatalf("%d entries: %v", maxStageEntries, err)
	}
	err := guardParse(t, many(maxStageEntries+1))
	if err == nil || !strings.Contains(err.Error(), "artifacts, limit") {
		t.Fatalf("%d entries: %v", maxStageEntries+1, err)
	}
	// A VALID document padded past the byte limit: without the size guard it
	// would parse, so only the guard can refuse it.
	doc, _ := json.Marshal(guardPlan())
	padded := append(doc, bytes.Repeat([]byte(" "), maxStagePlanBytes)...)
	if _, err := parseStagePlan(padded); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("a padded plan: %v", err)
	}
}

func TestLoadStagePlanRefusesWhatItCannotExtend(t *testing.T) {
	when := time.Unix(1000, 0)
	write := func(dir string, p stagePlan) {
		b, _ := json.Marshal(p)
		if err := os.WriteFile(filepath.Join(dir, stagePlanName), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := guardPlan()
	old.Time = 1000
	same := func() string { d := t.TempDir(); write(d, old); return d }

	if p, err := loadStagePlan(same(), old.Dist, old.Platform, when); err != nil || p.Dist != old.Dist {
		t.Fatalf("the same plan: %v", err)
	}
	for _, c := range []struct {
		name, dist, platform string
		when                 time.Time
	}{
		{"another destination", "oci://elsewhere/y", old.Platform, when},
		{"another platform", old.Dist, "linux/aarch64", when},
		{"another time", old.Dist, old.Platform, when.Add(time.Second)},
	} {
		if _, err := loadStagePlan(same(), c.dist, c.platform, c.when); err == nil || !strings.Contains(err.Error(), "is for") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Not "missing", so not a fresh plan: a path under a regular file, a directory
	// where the plan should be, and a file one byte over the cap.
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStagePlan(file, old.Dist, old.Platform, when); err == nil || !strings.Contains(err.Error(), "stage plan") {
		t.Errorf("under a regular file: %v", err)
	}
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, stagePlanName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStagePlan(d, old.Dist, old.Platform, when); err == nil {
		t.Error("a directory where the plan should be was taken for a fresh start")
	}
	small := filepath.Join(t.TempDir(), "p")
	if err := os.WriteFile(small, []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(small, 5); err == nil {
		t.Error("a file over the cap was read")
	}
	if b, err := readCapped(small, 6); err != nil || string(b) != "123456" {
		t.Errorf("a file at the cap: %q %v", b, err)
	}
	if _, err := readCapped(d, 10); err == nil {
		t.Error("a directory was read as a file")
	}
}

func TestWriteStagePlanAndHashFileRefuseWhatTheyCannotDo(t *testing.T) {
	p := guardPlan()
	bad := guardPlan()
	bad.Dist = "https://not-oci"
	if err := writeStagePlan(t.TempDir(), &bad); err == nil || !strings.Contains(err.Error(), "would refuse") {
		t.Errorf("a plan publish-stage would refuse was written: %v", err)
	}
	// A directory that does not exist yet is made: a run that built nothing has
	// not created it, and must still leave a (empty) plan.
	fresh := filepath.Join(t.TempDir(), "not", "yet")
	if err := writeStagePlan(fresh, &p); err != nil {
		t.Errorf("a missing directory was not made: %v", err)
	} else if _, err := os.Stat(filepath.Join(fresh, stagePlanName)); err != nil {
		t.Errorf("no plan in the made directory: %v", err)
	}
	blocker := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeStagePlan(filepath.Join(blocker, "sub"), &p); err == nil {
		t.Error("a directory could not be made under a regular file, yet the plan was written")
	}
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, stagePlanName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStagePlan(d, &p); err == nil {
		t.Error("renamed over a directory")
	}
	if left, _ := filepath.Glob(filepath.Join(d, stagePlanName+".tmp*")); len(left) != 0 {
		t.Errorf("a failed write left %v behind", left)
	}
	if _, _, err := hashFile(filepath.Join(d, "missing")); err == nil {
		t.Error("hashed a file that is not there")
	}
	if _, _, err := hashFile(d); err == nil {
		t.Error("hashed a directory")
	}
}

func TestAddBuiltRefusesWhatItCannotRecord(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.org", "v1.0.tar.gz")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	opt := publishOptions{Project: "a.org", Version: "1.0", OS: "linux", Arch: "x86-64", Path: file}
	mk := func() *stagePlan { p := guardPlan(); return &p }
	if err := mk().addBuilt(dir, opt); err != nil {
		t.Fatalf("a good artifact: %v", err)
	}
	rel := opt
	if err := mk().addBuilt("relative/dir", rel); err == nil {
		t.Error("a path that cannot be made relative to the stage was recorded")
	}
	gone := opt
	gone.Path = filepath.Join(dir, "gone.tar.gz")
	if err := mk().addBuilt(dir, gone); err == nil {
		t.Error("a file that is not there was recorded")
	}
	badName := opt
	badName.Project = "NOT VALID"
	if err := mk().addBuilt(dir, badName); err == nil {
		t.Error("an entry the parser would refuse was recorded")
	}
	// A re-run of the same address replaces its entry; another address is added.
	p := mk()
	for i := 0; i < 2; i++ {
		if err := p.addBuilt(dir, opt); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.Artifacts) != 1 {
		t.Errorf("a re-run listed the artifact %d times", len(p.Artifacts))
	}
	other := opt
	other.Version = "2.0"
	if err := p.addBuilt(dir, other); err != nil || len(p.Artifacts) != 2 {
		t.Errorf("another version: %v, %d entries", err, len(p.Artifacts))
	}
}

func TestReadStagedRefusesANonRegularFileByName(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x.tar.gz"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "x.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Size agrees with the plan, so only the file-type check can say no.
	_, err = readStaged(root, stageEntry{File: "x.tar.gz", Size: st.Size(), SHA256: strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v", err)
	}
}

func TestPublishStageExitCodesForWhatGoesWrong(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := runPublishStage(args, &out, &errb)
		return code, errb.String()
	}
	dist := []string{"--to", stageDist, "--allow-unsigned"}
	if code, _ := run(append([]string{r.h.artifacts, "--nope"}, dist...)...); code != 2 {
		t.Errorf("an unknown flag: code %d, want 2", code)
	}
	if code, e := run(append([]string{filepath.Join(t.TempDir(), "none")}, dist...)...); code != 1 || !strings.Contains(e, "publish-stage:") {
		t.Errorf("a stage directory that is not there: code %d %s", code, e)
	}
	if code, _ := run(append([]string{t.TempDir()}, dist...)...); code != 1 {
		t.Errorf("a directory with no plan: code %d, want 1", code)
	}
	asDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(asDir, stagePlanName), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _ := run(append([]string{asDir}, dist...)...); code != 1 {
		t.Errorf("a plan that is a directory: code %d, want 1", code)
	}
	if code, e := run(r.h.artifacts, "--to", stageDist, "--sign", filepath.Join(t.TempDir(), "no-key")); code != 1 || !strings.Contains(e, "publish-stage:") {
		t.Errorf("a key file that is not there: code %d %s", code, e)
	}
	if code, e := run(append([]string{r.h.artifacts, "--advisories", t.TempDir()}, dist...)...); code != 1 || !strings.Contains(e, "publish-stage:") {
		t.Errorf("an advisory tree with nothing in it: code %d %s", code, e)
	}
	if len(r.pushes) != 0 {
		t.Fatalf("pushed %d artifact(s) while refusing", len(r.pushes))
	}
	factoryPublish = func(publishOptions) (string, ocispec.Descriptor, error) {
		return "", ocispec.Descriptor{}, fmt.Errorf("registry down")
	}
	if code, e := run(append([]string{r.h.artifacts}, dist...)...); code != 1 || !strings.Contains(e, "registry down") {
		t.Errorf("a publish that failed: code %d %s", code, e)
	}
}

func TestStageOnlyReportsWhatItCouldNotStage(t *testing.T) {
	// The artifact path the build returns does not exist: it cannot be hashed,
	// so it is a failure of that build and is not in the plan.
	r := newStageRig(t)
	factoryBuild = func(_ *build.Runner, p build.Plan, _ *pantry.Recipe, project string, _, _ target.Target, out string) (build.Result, error) {
		return build.Result{Version: p.Version, Concrete: p.Concrete, SpecHash: p.SpecHash, ArtifactPath: filepath.Join(out, "missing.tar.gz")}, nil
	}
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--max-versions", "1", "--to", stageDist)
	data, err := os.ReadFile(filepath.Join(r.h.artifacts, stagePlanName))
	if err != nil {
		t.Fatalf("code %d: %v\n%s\n%s", code, err, r.h.out.String(), r.h.errb.String())
	}
	p, err := parseStagePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Artifacts) != 0 {
		t.Fatalf("an artifact that could not be hashed is in the plan: %+v", p.Artifacts)
	}
	all := r.h.out.String() + r.h.errb.String()
	if !strings.Contains(all, "STAGE FAIL") {
		t.Errorf("the failure does not say it was the staging:\n%s", all)
	}
	if strings.Contains(all, "✅ BUILT") || !strings.Contains(all, "0 built, 0 skipped, 1 failed") {
		t.Errorf("an artifact that could not be staged was counted as built (code %d):\n%s", code, all)
	}
}

// Each refusal below is also reached by a LATER check that would say no for
// another reason, so the assertions read the reason: a deleted guard then changes
// the message and not just the exit code.
func TestRefusalsNameTheirOwnReason(t *testing.T) {
	// The spec string is unparseable, which is not the same refusal as a spec that
	// parses and does not round-trip.
	if _, err := (stageEntry{Spec: "not a spec"}).concrete(); err == nil || strings.Contains(err.Error(), "canonical") {
		t.Errorf("an unparseable spec: %v", err)
	}
	dir := t.TempDir()
	if _, _, err := hashFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("hashing a missing file: %v", err)
	}
	p := guardPlan()
	if err := p.addBuilt("relative/dir", publishOptions{Project: "a.org", Version: "1.0", OS: "linux", Arch: "x86-64", Path: filepath.Join(dir, "a.tar.gz")}); err == nil || !strings.Contains(err.Error(), "relative") {
		t.Errorf("a path with no relative form: %v", err)
	}
	if err := p.addBuilt(dir, publishOptions{Project: "a.org", Version: "1.0", OS: "linux", Arch: "x86-64", Path: filepath.Join(dir, "gone.tar.gz")}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("recording a missing file: %v", err)
	}
	blocker := filepath.Join(dir, "f")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeStagePlan(filepath.Join(blocker, "sub"), &p); err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Errorf("a directory under a regular file: %v", err)
	}
	if os.Getuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := writeStagePlan(ro, &p); err == nil || !strings.Contains(err.Error(), "permission") {
			t.Errorf("a read-only directory: %v", err)
		}
	}
	bad := filepath.Join(dir, "bad")
	if err := os.Mkdir(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, stagePlanName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStagePlan(bad, "oci://x/y", "linux/x86-64", time.Unix(1, 0)); err == nil || !strings.Contains(err.Error(), "not one this run can extend") {
		t.Errorf("an unreadable existing plan: %v", err)
	}
	_, _, err := publishArtifact(publishOptions{Dist: stageDist, Project: "a.org", Version: "1.0", OS: "linux", Arch: "x86-64", Path: filepath.Join(dir, "gone.tar.gz")})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("publishing a missing file: %v", err)
	}
}

// A call that fails must leave neither a half plan nor a temporary file, and the
// error must be the call's own.
func TestWriteStagePlanFailsCleanlyAtEachCall(t *testing.T) {
	boom := errors.New("injected")
	cases := []struct {
		name string
		set  func()
	}{
		{"marshal", func() { stageMarshal = func(any, string, string) ([]byte, error) { return nil, boom } }},
		{"write", func() { stageWrite = func(*os.File, []byte) (int, error) { return 0, boom } }},
		{"close", func() {
			stageClose = func(f *os.File) error { f.Close(); return boom }
		}},
		{"chmod", func() { stageChmod = func(string, os.FileMode) error { return boom } }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldM, oldW, oldC, oldH := stageMarshal, stageWrite, stageClose, stageChmod
			t.Cleanup(func() { stageMarshal, stageWrite, stageClose, stageChmod = oldM, oldW, oldC, oldH })
			c.set()
			dir := t.TempDir()
			p := guardPlan()
			if err := writeStagePlan(dir, &p); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the injected one", err)
			}
			left, _ := os.ReadDir(dir)
			if len(left) != 0 {
				t.Errorf("a failed write left %d file(s) behind", len(left))
			}
		})
	}
}

func TestReadStagedFailsAtEachCall(t *testing.T) {
	dir := t.TempDir()
	body := []byte("payload")
	if err := os.WriteFile(filepath.Join(dir, "a.tar.gz"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sum := sha256.Sum256(body)
	e := stageEntry{File: "a.tar.gz", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	if b, err := readStaged(root, e); err != nil || string(b) != "payload" {
		t.Fatalf("the good file: %q %v", b, err)
	}
	boom := errors.New("injected")
	oldS, oldR := stageStat, stageReadAll
	t.Cleanup(func() { stageStat, stageReadAll = oldS, oldR })
	stageStat = func(*os.File) (fs.FileInfo, error) { return nil, boom }
	if _, err := readStaged(root, e); !errors.Is(err, boom) {
		t.Errorf("stat: %v", err)
	}
	stageStat = oldS
	stageReadAll = func(*os.File, int64) ([]byte, error) { return nil, boom }
	if _, err := readStaged(root, e); !errors.Is(err, boom) {
		t.Errorf("read: %v", err)
	}
	// The file shrank between the size check and the read, to bytes that still
	// have the planned digest only if the length were not checked first.
	stageReadAll = func(*os.File, int64) ([]byte, error) { return body[:3], nil }
	if _, err := readStaged(root, e); err == nil || !strings.Contains(err.Error(), "changed size") {
		t.Errorf("a short read: %v", err)
	}
}

func TestPublishStageSaysWhyItRefused(t *testing.T) {
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := runPublishStage(args, &out, &errb)
		return code, errb.String()
	}
	to := []string{"--to", stageDist, "--allow-unsigned"}
	if code, e := run(append([]string{t.TempDir(), "--nope"}, to...)...); code != 2 || strings.Contains(e, "usage: zpkb publish-stage") {
		t.Errorf("an unknown flag is the flag package's refusal, not the usage line: %d %s", code, e)
	}
	if code, e := run(append([]string{filepath.Join(t.TempDir(), "none")}, to...)...); code != 1 || !strings.Contains(e, "no such file") {
		t.Errorf("a stage directory that is not there: %d %s", code, e)
	}
	if code, e := run(append([]string{t.TempDir()}, to...)...); code != 1 || !strings.Contains(e, "no such file") {
		t.Errorf("a directory with no plan: %d %s", code, e)
	}
	asDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(asDir, stagePlanName), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, e := run(append([]string{asDir}, to...)...); code != 1 || !strings.Contains(e, "is a directory") {
		t.Errorf("a plan that is a directory: %d %s", code, e)
	}
	garbage := t.TempDir()
	if err := os.WriteFile(filepath.Join(garbage, stagePlanName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, e := run(append([]string{garbage}, to...)...); code != 1 || !strings.Contains(e, "publish-stage: ") || strings.Contains(e, "no such file") {
		t.Errorf("a plan that is not json: %d %s", code, e)
	}
}

func TestStageOnlyFailsWhenThePlanCannotBeWritten(t *testing.T) {
	r := newStageRig(t)
	inner := factoryBuild
	factoryBuild = func(rn *build.Runner, p build.Plan, rec *pantry.Recipe, project string, a, b target.Target, out string) (build.Result, error) {
		// A directory appears where the plan is to be renamed to.
		if err := os.MkdirAll(filepath.Join(r.h.artifacts, stagePlanName), 0o755); err != nil {
			t.Fatal(err)
		}
		return inner(rn, p, rec, project, a, b, out)
	}
	if code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--max-versions", "1", "--to", stageDist); code != 1 {
		t.Fatalf("code = %d, want 1 when the plan cannot be written\n%s", code, r.h.errb.String())
	}
}

func TestPublishArtifactWithoutTarballReadsThePathAndRefusesWhenItCannot(t *testing.T) {
	_, _, err := publishArtifact(publishOptions{Dist: stageDist, Project: "a.org", Version: "1.0", OS: "linux", Arch: "x86-64",
		Path: filepath.Join(t.TempDir(), "gone.tar.gz")})
	if err == nil {
		t.Fatal("published a file that is not there")
	}
}
