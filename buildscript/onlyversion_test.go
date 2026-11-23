package buildscript

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// runOnlyVersion renders a test script for lz4.org whose environment, as the
// eval leaves it, holds an OLDER lz4.org beside the build under test, runs it
// for real, and returns what the test body saw and what was said on stderr.
func runOnlyVersion(t *testing.T, project string, other bool) (seen map[string]string, stderr string) {
	t.Helper()
	root := t.TempDir()
	under := filepath.Join(root, "lz4.org", "v1.11.1-hnew")
	old := filepath.Join(root, "lz4.org", "v1.10.0-hold")
	zlib := filepath.Join(root, "zlib.net", "v1.3.1-hz")
	lookalike := filepath.Join(root, "xlz4.org", "v1.0.0-hx") // same tail, another project
	for _, d := range []string{under + "/include", under + "/lib/pkgconfig", old + "/include", old + "/lib/pkgconfig", zlib + "/include", lookalike + "/include"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// What the environment's closure exports: the compiler's closure carries the
	// OLD lz4.org, the package under test is absent from it.
	oldEntries := func(sub string) string {
		if !other {
			return ""
		}
		return old + sub + ":"
	}
	stub := `zpkx_stub() {
  echo 'export CPATH="` + oldEntries("/include") + zlib + `/include:` + lookalike + `/include"'
  echo 'export LIBRARY_PATH="` + oldEntries("/lib") + `/nowhere/lib"'
  echo 'export PKG_CONFIG_PATH="` + oldEntries("/lib/pkgconfig") + zlib + `/lib/pkgconfig"'
  echo 'export CMAKE_PREFIX_PATH="` + oldEntries("") + zlib + `"'
}
`
	body := `echo "CPATH=$CPATH"; echo "LIBRARY_PATH=$LIBRARY_PATH"; echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"; echo "CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH"`
	s := stub + WrapTest(TestWrapOptions{
		UserScript:    body,
		Package:       "", // staged: the package is not asked of any registry
		PackagePrefix: under,
		Project:       project,
		Deps:          []string{"llvm.org"},
		Home:          filepath.Join(root, "home"), Sandbox: filepath.Join(root, "box"),
		ZpkxBin: "zpkx_stub", Host: linuxHost(),
	})
	f, err := syntax.NewParser().Parse(strings.NewReader(s), "test.sh")
	if err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	var out, errb bytes.Buffer
	r, err := interp.New(interp.Env(expand.ListEnviron(os.Environ()...)), interp.StdIO(nil, &out, &errb))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), f); err != nil {
		t.Fatalf("run: %v\nstderr: %s\n%s", err, errb.String(), s)
	}
	seen = map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		k, v, _ := strings.Cut(l, "=")
		seen[k] = v
	}
	return seen, errb.String()
}

// ⛔ Smoke run 45085969313: the staged lz4.org 1.11.1 printed
// `header 11000 but library 11101`, because the environment held an older
// lz4.org too and its headers won. The package under test must be the only
// version of its project on any search path.
func TestTestEnvironmentHoldsOnlyTheVersionUnderTest(t *testing.T) {
	seen, stderr := runOnlyVersion(t, "lz4.org", true)
	for _, k := range []string{"CPATH", "LIBRARY_PATH", "PKG_CONFIG_PATH", "CMAKE_PREFIX_PATH"} {
		if strings.Contains(seen[k], "v1.10.0") {
			t.Errorf("%s still holds the other version: %s", k, seen[k])
		}
	}
	// The build under test is first, then what else the environment had.
	cpath := strings.Split(seen["CPATH"], ":")
	if len(cpath) < 2 || !strings.HasSuffix(cpath[0], "lz4.org/v1.11.1-hnew/include") {
		t.Errorf("the build under test is not first on CPATH: %v", cpath)
	}
	if !strings.Contains(seen["CPATH"], "zlib.net/v1.3.1-hz/include") || !strings.Contains(seen["CPATH"], "xlz4.org/v1.0.0-hx/include") {
		t.Errorf("an unrelated project was taken off CPATH: %s", seen["CPATH"])
	}
	if !strings.HasPrefix(seen["LIBRARY_PATH"], filepath.Join(filepath.Dir(cpath[0]), "lib")) {
		t.Errorf("the build under test is not first on LIBRARY_PATH: %s", seen["LIBRARY_PATH"])
	}
	if !strings.Contains(seen["PKG_CONFIG_PATH"], "v1.11.1-hnew/lib/pkgconfig") {
		t.Errorf("the build under test is not on PKG_CONFIG_PATH: %s", seen["PKG_CONFIG_PATH"])
	}
	// Said, not silent: a dependency that needs the other version is reported.
	if !strings.Contains(stderr, "v1.10.0-hold") || !strings.Contains(stderr, "other versions") {
		t.Errorf("the dropped version is not reported on stderr: %q", stderr)
	}
}

// With nothing else of the project in the environment nothing is dropped, and
// nothing is said.
func TestTestEnvironmentWithOneVersionSaysNothing(t *testing.T) {
	seen, stderr := runOnlyVersion(t, "lz4.org", false)
	if stderr != "" {
		t.Errorf("stderr should be empty: %q", stderr)
	}
	if !strings.Contains(seen["CPATH"], "lz4.org/v1.11.1-hnew/include") {
		t.Errorf("CPATH: %s", seen["CPATH"])
	}
}

// Without the project name nothing is pruned: the control for the guard above.
func TestTestEnvironmentUnprunedWithoutAProject(t *testing.T) {
	seen, _ := runOnlyVersion(t, "", true)
	if !strings.Contains(seen["CPATH"], "v1.10.0") {
		t.Errorf("control: the other version should still be there: %s", seen["CPATH"])
	}
}
