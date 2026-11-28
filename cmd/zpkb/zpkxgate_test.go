//go:build !windows

package main

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The factory tests that stage a seeded plan run no zpkx; the version gate is
// stubbed for them. The tests below put the real readers back.
func init() {
	readZpkxModuleVersion = func(string) (string, error) { return "v" + minZpkxVersion, nil }
	queryZpkxVersion = func(string) (string, error) { return minZpkxVersion, nil }
}

func realReaders(t *testing.T) {
	t.Helper()
	om, oq := readZpkxModuleVersion, queryZpkxVersion
	readZpkxModuleVersion, queryZpkxVersion = moduleVersionOf, zpkxVersionOf
	t.Cleanup(func() { readZpkxModuleVersion, queryZpkxVersion = om, oq })
}

// moduleVersionIs makes the build-info reader answer v (the seam).
func moduleVersionIs(t *testing.T, v string) {
	t.Helper()
	old := readZpkxModuleVersion
	readZpkxModuleVersion = func(string) (string, error) { return v, nil }
	t.Cleanup(func() { readZpkxModuleVersion = old })
}

// installAt builds a tiny Go program with `go install` at module version v, from
// a file:// module proxy, so the binary's build info really carries Main.Version
// = v — exactly what `go install github.com/go-zpkg/zpkx@vX.Y.Z` produces.
func installAt(t *testing.T, v string) string {
	t.Helper()
	root := t.TempDir()
	const mod = "example.test/fakezpkx"
	vdir := filepath.Join(root, "proxy", mod, "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	gomod := "module " + mod + "\n\ngo 1.20\n"
	for name, body := range map[string]string{
		mod + "@" + v + "/go.mod":  gomod,
		mod + "@" + v + "/main.go": "package main\n\nfunc main() {}\n",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		v + ".info": []byte(`{"Version":"` + v + `","Time":"2026-01-01T00:00:00Z"}`),
		v + ".mod":  []byte(gomod),
		v + ".zip":  zb.Bytes(),
		"list":      []byte(v + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(vdir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(root, "bin")
	cmd := exec.Command("go", "install", mod+"@"+v)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=file://"+filepath.Join(root, "proxy"), "GOSUMDB=off", "GOFLAGS=-mod=mod -modcacherw",
		"GOBIN="+bin, "GOPATH="+filepath.Join(root, "gopath"), "GOTOOLCHAIN=local", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		// The lanes that run the test binary in a VM or under qemu have no
		// usable Go toolchain; the native lanes do, and must not skip silently.
		if p := runtime.GOOS + "/" + runtime.GOARCH; p != "linux/amd64" && p != "darwin/arm64" {
			t.Skipf("no usable go toolchain on %s: %v\n%s", p, err, out)
		}
		t.Fatalf("go install %s@%s: %v\n%s", mod, v, err, out)
	}
	return filepath.Join(bin, "fakezpkx")
}

// scriptZpkx is a stand-in for a build that carries no Go build info; it prints
// the given --version line and appends every other call to a log.
func scriptZpkx(t *testing.T, versionLine string) (bin, log string) {
	t.Helper()
	log = filepath.Join(t.TempDir(), "calls")
	bin = fakeZpkx(t, "if [ \"$1\" = --version ]; then echo '"+versionLine+"'; exit 0; fi\necho \"$@\" >> "+log+"\nexit 0\n")
	return bin, log
}

// The incident: go-zpkg/packages installed zpkx with `go install …@v0.45.0`,
// which prints "dev" for --version. The build info is what tells.
func TestARealGoInstalledOlderZpkxIsRefusedNamingBothVersions(t *testing.T) {
	realReaders(t)
	bin := installAt(t, "v0.45.0")
	if out, err := exec.Command(bin).CombinedOutput(); err != nil {
		t.Fatalf("the stand-in does not run: %v %s", err, out)
	}
	var warn bytes.Buffer
	err := requireZpkx(bin, &warn)
	if err == nil {
		t.Fatal("a go-installed v0.45.0 was accepted")
	}
	for _, want := range []string{"v0.45.0", minZpkxVersion, "too old"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not contain %q: %v", want, err)
		}
	}
}

func TestARealGoInstalledMinimumAndNewerZpkxAreAccepted(t *testing.T) {
	realReaders(t)
	for _, v := range []string{"v" + minZpkxVersion, "v0.47.0"} {
		var warn bytes.Buffer
		if err := requireZpkx(installAt(t, v), &warn); err != nil {
			t.Errorf("%s was refused: %v", v, err)
		}
		if warn.Len() != 0 {
			t.Errorf("%s: unexpected output %q", v, warn.String())
		}
	}
}

// Every component counts: a lower minor or patch is older whatever the rest is.
func TestTheComparisonIsMajorMinorPatch(t *testing.T) {
	for v, older := range map[string]bool{
		"v0.45.0": true, "v0.46.0": true, "v0.9.99": true, "v0.45.9": true, "v0.46.1": false,
		"v0.46.2": false, "v0.47.0": false, "v1.0.0": false, "v0.100.0": false,
		"v0.46.2-0.20260101000000-abcdef123456": false, "v0.46.0-rc.1": true,
	} {
		moduleVersionIs(t, v)
		err := requireZpkx("zpkx", &bytes.Buffer{})
		if older != (err != nil) {
			t.Errorf("%s: older=%v err=%v", v, older, err)
		}
		if older && (!strings.Contains(err.Error(), v) || !strings.Contains(err.Error(), minZpkxVersion)) {
			t.Errorf("%s: the refusal does not name both versions: %v", v, err)
		}
	}
}

// "(devel)", a non-Go binary and an unreadable answer are REFUSED by default;
// a stamped --version is read; the opt-in accepts and says so.
func TestAnUnversionedZpkxIsRefusedUnlessOptedIn(t *testing.T) {
	realReaders(t)
	t.Setenv(allowUnversionedZpkxEnv, "")

	// A script has no build info and says "dev": nothing to go on.
	bin, _ := scriptZpkx(t, "zpkx dev")
	err := requireZpkx(bin, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot tell which") || !strings.Contains(err.Error(), allowUnversionedZpkxEnv) {
		t.Errorf("an unversioned zpkx: %v", err)
	}
	for _, body := range []string{"echo hello world\n", "exit 0\n", "echo zpkx\n", "echo 'other 1.2.3'\n", "echo 'zpkx banana'\n"} {
		if err := requireZpkx(fakeZpkx(t, body), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot tell which") {
			t.Errorf("%q: %v", body, err)
		}
	}
	if err := requireZpkx(filepath.Join(t.TempDir(), "absent"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot tell which") {
		t.Errorf("a zpkx that cannot be run: %v", err)
	}

	// A "(devel)" build answers by what it stamped.
	moduleVersionIs(t, "(devel)")
	old, _ := scriptZpkx(t, "zpkx 0.45.0")
	if err := requireZpkx(old, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "0.45.0") || !strings.Contains(err.Error(), minZpkxVersion) {
		t.Errorf("a (devel) zpkx stamped 0.45.0: %v", err)
	}
	cur, _ := scriptZpkx(t, "zpkx "+minZpkxVersion)
	if err := requireZpkx(cur, &bytes.Buffer{}); err != nil {
		t.Errorf("a (devel) zpkx stamped %s: %v", minZpkxVersion, err)
	}
	if err := requireZpkx(bin, &bytes.Buffer{}); err == nil {
		t.Error("a (devel) zpkx stamped dev was accepted")
	}

	// The opt-in accepts, and prints that it did.
	t.Setenv(allowUnversionedZpkxEnv, "1")
	var warn bytes.Buffer
	if err := requireZpkx(bin, &warn); err != nil {
		t.Errorf("the opt-in was refused: %v", err)
	}
	if !strings.Contains(warn.String(), "WARNING") || !strings.Contains(warn.String(), allowUnversionedZpkxEnv) {
		t.Errorf("the opt-in did not say so: %q", warn.String())
	}
	// The opt-in does not excuse an OLD zpkx.
	moduleVersionIs(t, "v0.45.0")
	if err := requireZpkx(bin, &bytes.Buffer{}); err == nil {
		t.Error("the opt-in accepted a known-old zpkx")
	}
}

func TestTheModuleVersionReaderReadsAGoInstall(t *testing.T) {
	if v, err := moduleVersionOf(installAt(t, "v0.45.0")); err != nil || v != "v0.45.0" {
		t.Errorf("moduleVersionOf a go-installed binary: %q %v", v, err)
	}
}

// The three readers, asserted on both sides of each guard.
func TestTheVersionReadersSayWhatTheyRead(t *testing.T) {
	if v, err := moduleVersionOf(fakeZpkx(t, "exit 0\n")); err == nil {
		t.Errorf("a script has no build info, got %q", v)
	}
	if v, err := moduleVersionOf(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Errorf("an absent file has no build info, got %q", v)
	}

	if v, err := zpkxVersionOf(fakeZpkx(t, "echo 'zpkx 1.2.3'\n")); err != nil || v != "1.2.3" {
		t.Errorf("zpkxVersionOf: %q %v", v, err)
	}
	if _, err := zpkxVersionOf(filepath.Join(t.TempDir(), "absent")); err == nil || !strings.Contains(err.Error(), "could not run") {
		t.Errorf("an absent zpkx: %v", err)
	}
	for _, body := range []string{"echo hello world\n", "exit 0\n", "echo zpkx\n", "echo 'other 1.2.3'\n", "echo 'zpkx 1.2.3 extra'\n"} {
		if v, err := zpkxVersionOf(fakeZpkx(t, body)); err == nil || !strings.Contains(err.Error(), "printed") {
			t.Errorf("%q: %q %v", body, v, err)
		}
	}

	for s, want := range map[string][3]int{"1.2.3": {1, 2, 3}, "v0.46.1": {0, 46, 1}, "v1.2.3-rc.1": {1, 2, 3}, "1.2.3+b": {1, 2, 3}} {
		if got, ok := parseSemver(s); !ok || got != want {
			t.Errorf("parseSemver(%q) = %v %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "1", "1.2", "1.2.3.4", "1.2.x", "x.2.3", "1..3", "dev", "(devel)"} {
		if got, ok := parseSemver(s); ok {
			t.Errorf("parseSemver(%q) = %v, want a refusal", s, got)
		}
	}
}

// The gate is in the factory, before anything is built: an old zpkx stops a
// seeded run with the refusal, and zpkx is not run at all.
func TestTheFactoryRefusesASeededRunWithAnOlderZpkx(t *testing.T) {
	moduleVersionIs(t, "v0.45.0")
	t.Setenv("ZPKX_SEEDED", "oci://ghcr.io/go-pkgx/packages")
	r := newStageRig(t)
	oldLP := lookPath
	lookPath = func(s string) (string, error) { return s, nil }
	t.Cleanup(func() { lookPath = oldLP })
	bin, log := scriptZpkx(t, "zpkx dev")
	args := append([]string{"--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist, "--zpkx", bin}, ledgerFlags(t, testSeedEntries)...)
	code := r.h.run(t, args...)
	if code != 1 || !strings.Contains(r.h.errb.String(), "v0.45.0") || !strings.Contains(r.h.errb.String(), minZpkxVersion) {
		t.Errorf("code=%d err=%q", code, r.h.errb.String())
	}
	if b, err := os.ReadFile(log); err == nil {
		t.Errorf("zpkx was called under a refused run: %q", b)
	}
	if _, err := os.Stat(filepath.Join(r.h.artifacts, stagePlanName)); err == nil {
		t.Error("a plan was written under a refused run")
	}
}

// ci.yml's real-zpkx lane installs the zpkx this code is tested against; the
// constant must be that tag.
func TestMinZpkxVersionIsTheTagCIInstalls(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`go install github\.com/go-zpkg/zpkx@v(\d+\.\d+\.\d+)\b`).FindAllStringSubmatch(string(b), -1)
	if len(m) != 1 {
		t.Fatalf("expected exactly one `go install github.com/go-zpkg/zpkx@vX.Y.Z` in ci.yml, found %d", len(m))
	}
	if m[0][1] != minZpkxVersion {
		t.Errorf("ci.yml installs zpkx v%s but minZpkxVersion is %s", m[0][1], minZpkxVersion)
	}
}
