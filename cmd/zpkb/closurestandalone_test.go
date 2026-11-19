package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `closure --require-standalone`: how far step 1 of go-zpkg/packages#440 is,
// asked of the closure rather than of a whole tree.

const wholeRecipe = "versions:\n  github: a/x/tags\ndistributable:\n  url: https://x/x-{{version}}.tgz\nbuild: make\n"

// ⛔⛔ TestTheThreePopulationsPartitionTheClosure is the test that the first
// run of this flag would have failed, and it is why it is first here.
// `recipefile.ErrNoRecipe` covers a project DIRECTORY that holds no recipe; a
// project with no directory at all returns a bare `open …: no such file or
// directory`. Classifying only the sentinel put 18 of the base-toolchain
// closure's 20 absences under "unreadable: counted in neither population
// above" — an absence reported as something else, by the check written to stop
// exactly that.
//
// So the property asserted is arithmetic: every project lands in exactly one
// population, and they sum to the input. A count that does not add up is the
// one symptom that cannot be argued with.
func TestTheThreePopulationsPartitionTheClosure(t *testing.T) {
	overlay := t.TempDir()
	writeClosureRecipe(t, overlay, "whole.org", wholeRecipe)
	writeClosureRecipe(t, overlay, "frag.org", "dependencies:\n  whole.org: '*'\n")
	// An empty project DIRECTORY: this is the ErrNoRecipe shape.
	if err := os.MkdirAll(filepath.Join(overlay, "projects", "empty.org"), 0o755); err != nil {
		t.Fatal(err)
	}
	// And nothing at all for gone.org: the fs.ErrNotExist shape, which is the
	// one that was misfiled.
	order := []string{"whole.org", "frag.org", "empty.org", "gone.org"}

	var out, errb bytes.Buffer
	closureStandalone(order, overlay, -1, &out, &errb)
	got := out.String()
	if !strings.Contains(got, "4 project(s); 1 standalone in the overlay, 1 fragment(s), 2 absent from it") {
		t.Errorf("the populations do not partition the closure:\n%s", got)
	}
	// ⛔ AND NOTHING IS "UNREADABLE" HERE. Two of these four have no recipe and
	// one is incomplete; none of them is a file that failed to parse.
	if strings.Contains(got, "unreadable") || strings.Contains(errb.String(), "cannot be read") {
		t.Errorf("an absence is reported as unreadable:\n%s\n%s", got, errb.String())
	}
	if !strings.Contains(got, "empty.org") || !strings.Contains(got, "gone.org") {
		t.Errorf("an absent project is not named:\n%s", got)
	}
}

// TestAFragmentIsNamedWithWhatItLacks: the list is a work list, so it has to
// say what to write. The judgement is missingEssentials, shared with
// `lint --require-standalone` so the two cannot disagree.
func TestAFragmentIsNamedWithWhatItLacks(t *testing.T) {
	overlay := t.TempDir()
	writeClosureRecipe(t, overlay, "frag.org", "versions:\n  github: a/x/tags\n")

	var out, errb bytes.Buffer
	if code := closureStandalone([]string{"frag.org"}, overlay, -1, &out, &errb); code != 1 {
		t.Errorf("code = %d, want 1: a fragment in the closure is a failure", code)
	}
	for _, want := range []string{"frag.org", "states no distributable, no build",
		"merged underneath"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not say %q:\n%s", want, out.String())
		}
	}
}

// TestASetIsNotAFragment: a `members` recipe names a tree of packages by
// constraint and has no source of its own, so judging it by `distributable`
// would report every set as a fragment — including the base-toolchain set that
// is the root of the closure being measured.
func TestASetIsNotAFragment(t *testing.T) {
	overlay := t.TempDir()
	writeClosureRecipe(t, overlay, "set.org", "members:\n  whole.org: '*'\n")

	var out, errb bytes.Buffer
	if code := closureStandalone([]string{"set.org"}, overlay, -1, &out, &errb); code != 0 {
		t.Errorf("code = %d, want 0; stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "1 standalone") {
		t.Errorf("a set is not counted as standalone:\n%s", out.String())
	}
}

// ⚠ TestARecipeThatWillNotParseIsCountedApart: an unreadable file is neither
// ours-and-complete nor absent, and folding it into either would be a verdict
// about a file nothing has read.
func TestARecipeThatWillNotParseIsCountedApart(t *testing.T) {
	overlay := t.TempDir()
	writeClosureRecipe(t, overlay, "bad.org", "versions:\n  - [this is not\n   valid: yaml\n")

	var out, errb bytes.Buffer
	code := closureStandalone([]string{"bad.org"}, overlay, -1, &out, &errb)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "1 unreadable") {
		t.Errorf("the summary does not count it:\n%s", out.String())
	}
	if !strings.Contains(errb.String(), "counted in neither population") {
		t.Errorf("stderr does not say it is in neither population:\n%s", errb.String())
	}
	// It must NOT have been quietly called absent, which is the misfiling this
	// whole file is about, in the other direction.
	if strings.Contains(out.String(), "1 absent") {
		t.Errorf("an unparseable recipe was called absent:\n%s", out.String())
	}
}

// TestTheRatchetRefusesBothDirections, in `lint --max-fragments`'s shape and
// for its reason: a ceiling nobody lowers stops describing the closure, and
// then a regression hides in the slack.
func TestTheRatchetRefusesBothDirections(t *testing.T) {
	overlay := t.TempDir()
	writeClosureRecipe(t, overlay, "a.org", "versions:\n  github: a/x/tags\n")
	writeClosureRecipe(t, overlay, "b.org", "versions:\n  github: b/x/tags\n")
	order := []string{"a.org", "b.org"}

	for _, c := range []struct {
		name string
		max  int
		code int
		want string
	}{
		{"above the ceiling is a regression", 1, 1, "--max-fragments says 1"},
		{"below it is a ceiling to lower", 3, 1, "lower it to 2"},
		{"at it, the obligation is named", 2, 0, "at the stated ceiling of 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := closureStandalone(order, overlay, c.max, &out, &errb); code != c.code {
				t.Errorf("code = %d, want %d; stderr=%q", code, c.code, errb.String())
			}
			if !strings.Contains(errb.String(), c.want) {
				t.Errorf("stderr does not say %q:\n%s", c.want, errb.String())
			}
		})
	}
	// And with no ceiling stated, a clean closure passes.
	clean := t.TempDir()
	writeClosureRecipe(t, clean, "a.org", wholeRecipe)
	var out, errb bytes.Buffer
	if code := closureStandalone([]string{"a.org"}, clean, -1, &out, &errb); code != 0 {
		t.Errorf("a clean closure failed: code=%d stderr=%q", code, errb.String())
	}
}

// ⛔ TestItRefusesWithoutAnOverlay: the question is "which of these have a
// complete recipe OF OURS", and with no overlay there is no tree of ours to
// ask about. Answering "none are ours" would be a measurement of nothing.
func TestItRefusesWithoutAnOverlay(t *testing.T) {
	var out, errb bytes.Buffer
	if code := closureStandalone([]string{"a.org"}, "", -1, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "needs --overlay") {
		t.Errorf("the refusal does not name the missing flag: %q", errb.String())
	}
}

// TestRunClosureRequireStandaloneIsWired drives it through the command, which
// is the only thing that proves the flag reaches the function and that it is
// asked of the WALK's order rather than of a list typed beside it.
func TestRunClosureRequireStandaloneIsWired(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	// app depends on lib; the pantry has both, the overlay has a complete app
	// and nothing for lib — so the closure's two members land in two different
	// populations.
	writeClosureRecipe(t, pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	writeClosureRecipe(t, overlay, "app.org", wholeRecipe)

	var out, errb bytes.Buffer
	code := runClosure([]string{"--recipe-dir", pantry, "--overlay", overlay,
		"--require-standalone", "app.org"}, &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "2 project(s); 1 standalone in the overlay, 0 fragment(s), 1 absent") {
		t.Errorf("the walk's own order was not what was judged:\n%s", out.String())
	}
	// ⚠ And the ORDER must not also be printed: this flag replaces the order,
	// as --cycles and --constraints do, so a caller parsing one does not get
	// both.
	if strings.Contains(out.String(), "\napp.org\n") {
		t.Errorf("the order was emitted alongside the report:\n%s", out.String())
	}
}
