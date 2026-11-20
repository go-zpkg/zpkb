package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/build"
)

var dig = strings.Repeat("a", 64)

func pinRecipe(versions, dist, extra string) string {
	return "versions:\n" + versions + "distributable:\n" + dist + extra
}

// ⛔⛔ The defect that recurred 3 times on 2026-11-20: versions resolves a newer
// version than the one pinned, so the default build is a refusal.
func TestCheckNewestPinnedNamesTheNewestAndThePinnedSet(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.yml": pinRecipe(
		"  - 14.4.0\n  - 16.2.0\n",
		"  url: http://x/{{version.raw}}.tgz\n  sha256:\n    14.4.0: "+dig+"\n", "")})
	if rc, _, errb := lint(t, "--dir", dir); rc != 0 {
		t.Fatalf("without the flag nothing resolves: rc=%d\n%s", rc, errb)
	}
	rc, _, errb := lint(t, "--dir", dir, "--check-newest-pinned")
	if rc != 1 {
		t.Fatalf("rc=%d, want 1:\n%s", rc, errb)
	}
	for _, want := range []string{"acme.org: distributable: newest resolved version is 16.2.0",
		"pinned for 14.4.0 but not for 16.2.0"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q:\n%s", want, errb)
		}
	}
}

func TestCheckNewestPinnedPassesWhenTheNewestIsPinned(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.yml": pinRecipe(
		"  - 14.4.0\n  - 16.2.0\n",
		"  url: http://x/{{version.raw}}.tgz\n  sha256:\n    14.4.0: "+dig+"\n    16.2.0: "+dig+"\n", "")})
	if rc, _, errb := lint(t, "--dir", dir, "--check-newest-pinned"); rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

// A recipe that pins nothing is not asked anything, and does not even resolve:
// the resolver here would fail the test if it were called.
func TestCheckNewestPinnedSkipsARecipeThatPinsNothing(t *testing.T) {
	old := lintResolve
	lintResolve = func(any, string) (string, string, error) {
		t.Error("resolved a recipe that pins nothing")
		return "", "", nil
	}
	defer func() { lintResolve = old }()
	dir := lintTree(t, map[string]string{
		"a.org/package.yml": pinRecipe("  - 1.0.0\n", "  url: http://x/y.tgz\n", ""),
		"b.org/package.yml": pinRecipe("  - 1.0.0\n", "  - url: http://x/y.tgz\n", ""),
		"c.org/package.yml": "versions:\n  - 1.0.0\ndistributable: http://x/y.tgz\n",
	})
	if rc, _, errb := lint(t, "--dir", dir, "--check-newest-pinned"); rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

// A list-form distributable and a `sources:` entry (v0.92.0) are both read, and
// each is named by its position.
func TestCheckNewestPinnedReadsListDistributableAndSources(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.yml": pinRecipe(
		"  - 1.0.0\n  - 2.0.0\n",
		"  - url: http://m1/{{version.raw}}.tgz\n    sha256:\n      1.0.0: "+dig+"\n      2.0.0: "+dig+"\n"+
			"  - url: http://m2/{{version.raw}}.tgz\n    sha256:\n      1.0.0: "+dig+"\n",
		"sources:\n  - url: http://x/{{version.raw}}.patch\n    sha256:\n      1.0.0: "+dig+"\n"+
			"  - url: http://x/ok.patch\n    sha256: "+dig+"\n")})
	rc, _, errb := lint(t, "--dir", dir, "--check-newest-pinned")
	if rc != 1 {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
	for _, want := range []string{"distributable[1]: newest resolved version is 2.0.0",
		"sources[0]: newest resolved version is 2.0.0", "2 pin(s)"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q:\n%s", want, errb)
		}
	}
	for _, not := range []string{"distributable[0]", "sources[1]"} {
		if strings.Contains(errb, not) {
			t.Errorf("%q is pinned and must not be named:\n%s", not, errb)
		}
	}
}

// Unresolvable is not a pass: a check that could not read reports zero too.
func TestCheckNewestPinnedRefusesWhatItCannotResolve(t *testing.T) {
	old := lintResolve
	lintResolve = func(any, string) (string, string, error) { return "", "", errors.New("upstream gone") }
	defer func() { lintResolve = old }()
	dir := lintTree(t, map[string]string{"acme.org/package.yml": pinRecipe(
		"  - 1.0.0\n", "  url: http://x/y.tgz\n  sha256: "+dig+"\n", "")})
	rc, _, errb := lint(t, "--dir", dir, "--check-newest-pinned")
	if rc != 1 || !strings.Contains(errb, "acme.org: cannot resolve its newest version: upstream gone") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

func TestBuildPinnedDigestIsExported(t *testing.T) {
	if got, err := build.PinnedDigest(dig, "x"); err != nil || got != dig {
		t.Fatalf("got %q, %v", got, err)
	}
}
