package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deadOverrideDir writes a directory of logical overrides, one file per
// project, named as go-zpkg/packages names them.
func deadOverrideDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const (
	standaloneAcme = "versions { github = \"acme/acme\" }\n" +
		"distributable { url = \"https://acme.org/{{version}}.tar.gz\" }\n" +
		"build { script = \"make install\" }\n"
	acmeOverride = "project = \"acme.org\"\nwhy = \"needs m4\"\n" +
		"edits = [ { path = \"build.dependencies[\\\"gnu.org/m4\\\"]\", set = \"*\" } ]\n"
)

// ⛔⛔ go-zpkg/zpkb#516. A standalone recipe is built WITHOUT its logical
// override, so the override is dead — and it must be NAMED, with its file.
func TestLintNamesAnOverrideThatAStandaloneRecipeRetired(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	ov := deadOverrideDir(t, map[string]string{"acme.org.hcl": acmeOverride})
	rc, _, errb := lint(t, "--dir", dir, "--overrides", ov)
	if rc != 0 {
		t.Fatalf("a dead override is a WARNING by default: rc=%d\n%s", rc, errb)
	}
	for _, want := range []string{"1 override(s) are DEAD", "acme.org: acme.org.hcl",
		"fix MISSING from the recipe: build.dependencies[\"gnu.org/m4\"]"} {
		if !strings.Contains(errb, want) {
			t.Errorf("the warning does not say %q:\n%s", want, errb)
		}
	}
}

// The verdict tells the author what to do: nothing to carry, or a defect.
func TestLintDeadOverrideSaysWhetherTheRecipeHasItsFix(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": "versions { github = \"acme/acme\" }\n" +
		"distributable { url = \"https://acme.org/{{version}}.tar.gz\" }\n" +
		"build {\n  script = \"make install\"\n  dependencies = { \"gnu.org/m4\" = \"*\" }\n}\n"})
	ov := deadOverrideDir(t, map[string]string{"acme.org.hcl": acmeOverride})
	_, _, errb := lint(t, "--dir", dir, "--overrides", ov)
	if !strings.Contains(errb, "acme.org.hcl — fix already in the recipe") {
		t.Fatalf("the fix is in the recipe and the verdict must say so:\n%s", errb)
	}
}

func TestLintRefusesADeadOverrideWhenAsked(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	ov := deadOverrideDir(t, map[string]string{"acme.org.hcl": acmeOverride})
	rc, _, errb := lint(t, "--dir", dir, "--overrides", ov, "--require-live-overrides")
	if rc != 1 || !strings.Contains(errb, "acme.org.hcl") {
		t.Fatalf("rc=%d, want 1 naming the file:\n%s", rc, errb)
	}
}

// A FRAGMENT is still merged over upstream's recipe with the override applied,
// so its override is live; and an override for a project this tree does not
// carry is applied to upstream's recipe. Neither is dead.
func TestLintLeavesALiveOverrideAlone(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"acme.org/package.hcl": "dependencies = { \"openssl.org\" = \"^3\" }\n",
	})
	ov := deadOverrideDir(t, map[string]string{
		"acme.org.hcl": acmeOverride,
		"other.org.hcl": "project = \"other.org\"\nwhy = \"x\"\n" +
			"edits = [ { path = \"build.dependencies[\\\"gnu.org/m4\\\"]\", set = \"*\" } ]\n",
	})
	rc, out, errb := lint(t, "--dir", dir, "--overrides", ov, "--require-live-overrides")
	if rc != 0 || strings.Contains(errb, "DEAD") {
		t.Fatalf("no override is dead here: rc=%d\n%s", rc, errb)
	}
	// The denominator, so "none dead" is told from "none read".
	if !strings.Contains(out, "2 override(s) read from") {
		t.Errorf("the count read is missing:\n%s", out)
	}
}

func TestLintDeadOverridesAreOffWithoutTheFlag(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	rc, _, errb := lint(t, "--dir", dir)
	if rc != 0 || strings.Contains(errb, "DEAD") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

func TestLintRequireLiveNeedsTheDirectoryItJudges(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	if rc, _, errb := lint(t, "--dir", dir, "--require-live-overrides"); rc != 2 ||
		!strings.Contains(errb, "does nothing without") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

// An empty or wrong directory is not a clean one.
func TestLintRefusesAnEmptyOverridesDirectory(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	if rc, _, errb := lint(t, "--dir", dir, "--overrides", t.TempDir()); rc != 1 ||
		!strings.Contains(errb, "no override under") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

func TestLintRefusesAnUnreadableOverride(t *testing.T) {
	dir := lintTree(t, map[string]string{"acme.org/package.hcl": standaloneAcme})
	ov := deadOverrideDir(t, map[string]string{"bad.hcl": "this is = = not hcl"})
	if rc, _, _ := lint(t, "--dir", dir, "--overrides", ov); rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
}
