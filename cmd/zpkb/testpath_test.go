package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// ⛔ go-zpkg/packages#440: a green publish was followed by
//
//	"lz4": executable file not found in $PATH
//
// because the store held TWO builds of lz4.org 1.10.0 (a seed dependency and
// the one just made), `zpkx +lz4.org@=1.10.0` cannot say which, and the
// environment it printed left the package's bin/ off PATH without a word.
//
// The scenario is built from the store's own helpers — artifact.StoreHash,
// artifact.StoreBuildPrefix, artifact.ResolveBuild — and not from a
// spelled-out `<store>/<project>/v<version>-h…`, the kind of literal that hid
// zpkb#528 and artifact#243. The fake zpkx prints an environment with nothing
// in it, which is what the real one printed for an ambiguous version.
func TestRunRecipeTestFindsTheBuildUnderTestAmongSeveralOfOneVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake zpkx and the tool under test are shell scripts")
	}
	dir := testTestbed(t)
	store := os.Getenv("ZPKG_DIR")
	v := artifact.Ver{Raw: "1.2.3"}

	// testTestbed already installed one build of proj.org 1.2.3: the
	// bystander. The build under test is a second, with its own hash.
	hash := artifact.StoreHash(v, "digest:the-build-under-test", "")
	underTest := artifact.StoreBuildPrefix(store, "proj.org", v, hash)
	if err := os.MkdirAll(filepath.Join(underTest, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := len(artifact.InstalledBuilds("proj.org", store)); got != 2 {
		t.Fatalf("the scenario needs two builds of one version, the store holds %d", got)
	}
	if _, ok := artifact.ResolveBuild(store, "proj.org", v); ok {
		t.Fatal("ResolveBuild answered for an ambiguous version: the premise of this test is gone")
	}
	if err := os.WriteFile(filepath.Join(underTest, "bin", "proj"),
		[]byte("#!/bin/sh\necho proj 1.2.3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	zpkx := filepath.Join(dir, "zpkx")
	if err := os.WriteFile(zpkx, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec, err := recipefile.LoadFile(writeTestRecipe(t, okRecipe))
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := target.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	state, err := runRecipeTest(testRequest{
		Recipe: rec, RecipeDir: dir, Project: "proj.org", Version: "1.2.3",
		BuildHash: hash, Target: tgt, ZpkxBin: zpkx,
		Run: runBashLimited(0, &out, &out),
	}, &out, &out)
	if state != testPassed {
		t.Fatalf("state %s, err %v: the build under test was not on PATH\n%s", state, err, out.String())
	}
}
