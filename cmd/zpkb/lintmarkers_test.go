package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// markerDir writes an empty marker file per name and returns the directory.
func markerDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".fragments")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func nestedFragmentTree(t *testing.T) string {
	t.Helper()
	return lintTree(t, map[string]string{
		"a.org/package.hcl":       "dependencies = { \"openssl.org\" = \"^3\" }\n",
		"crates.io/x/package.hcl": "dependencies = { \"zlib.net\" = \"*\" }\n",
		"c.org/package.hcl": "versions { github = \"c/c\" }\n" +
			"distributable { url = \"https://c.org/{{version}}.tar.gz\" }\n" +
			"build { script = \"make install\" }\n",
	})
}

// The markers equal the fragments, nested names included: the run passes and
// still names the fragments, as the ceiling does.
func TestLintFragmentsDirAcceptsTheEqualSet(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--fragments-dir", markerDir(t, "a.org", "crates.io/x"))
	if rc != 0 {
		t.Fatalf("equal sets must pass: rc=%d\n%s", rc, errb)
	}
	if !strings.Contains(errb, "crates.io/x") {
		t.Errorf("a tolerated fragment must still be named:\n%s", errb)
	}
}

// A fragment with no marker is a regression, and it is named.
func TestLintFragmentsDirRefusesAFragmentWithNoMarker(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--fragments-dir", markerDir(t, "a.org"))
	if rc != 1 {
		t.Fatalf("an unmarked fragment must fail: rc=%d\n%s", rc, errb)
	}
	if !strings.Contains(errb, "crates.io/x is a fragment with no marker") {
		t.Errorf("the refusal must name the fragment:\n%s", errb)
	}
	if strings.Contains(errb, "delete this marker") {
		t.Errorf("nothing is stale here:\n%s", errb)
	}
}

// A marker for a recipe that stands alone (or does not exist) is stale and
// says to delete it: the direction a ceiling covers with "lower it".
func TestLintFragmentsDirRefusesAMarkerForAWholeRecipe(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--fragments-dir", markerDir(t, "a.org", "crates.io/x", "c.org", "gone.org/deep"))
	if rc != 1 {
		t.Fatalf("a stale marker must fail: rc=%d\n%s", rc, errb)
	}
	for _, want := range []string{"c.org", "gone.org", "delete this marker"} {
		if !strings.Contains(errb, want) {
			t.Errorf("the refusal must name %q:\n%s", want, errb)
		}
	}
}

// A directory that is not there is an error, never an empty set.
func TestLintFragmentsDirMissingDirIsRefused(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--fragments-dir", filepath.Join(t.TempDir(), "nope"))
	if rc != 2 {
		t.Fatalf("a missing directory must be refused: rc=%d\n%s", rc, errb)
	}
}

func TestLintFragmentsDirIsExclusiveWithMaxFragments(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--max-fragments", "2", "--fragments-dir", markerDir(t, "a.org", "crates.io/x"))
	if rc != 2 || !strings.Contains(errb, "give one") {
		t.Fatalf("both flags must be refused: rc=%d\n%s", rc, errb)
	}
}

func TestLintFragmentsDirNeedsTheCheckItLists(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--fragments-dir", markerDir(t))
	if rc != 2 || !strings.Contains(errb, "does nothing without it") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

// No markers at all against a tree with fragments is every one of them a
// regression, not a pass.
func TestLintFragmentsDirEmptyDirToleratesNothing(t *testing.T) {
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone",
		"--fragments-dir", markerDir(t))
	if rc != 1 || !strings.Contains(errb, "a.org is a fragment with no marker") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

func TestLintFragmentsDirAFileIsNotADirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rc, _, errb := lint(t, "--dir", nestedFragmentTree(t), "--require-standalone", "--fragments-dir", f)
	if rc != 2 || !strings.Contains(errb, "not a directory") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}
