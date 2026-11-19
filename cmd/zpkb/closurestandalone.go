package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/recipefile"
)

// How far step 1 of go-zpkg/packages#440 actually is, asked of the SET THAT
// MATTERS rather than of a whole tree.
//
// ⛔⛔ `lint --require-standalone` ANSWERS A QUESTION NOBODY IS BLOCKED ON. Run
// over go-zpkg/recipes on 2026-11-19 it says 185 of 253 cannot resolve alone —
// a true number about a tree that holds recipes for projects no base toolchain
// needs. The campaign's measure is the base-toolchain closure, so the number
// that says whether step 1 is done is the one taken over THAT list: of the
// projects this build needs, how many are ours and complete?
//
// ⭐ AND IT IS A THREE-WAY SPLIT, NOT A COUNT, which is the whole reason this
// is worth a flag. A closure member is in one of three states and they need
// different work:
//
//   - standalone in our overlay — done;
//   - a FRAGMENT in our overlay — an amendment that resolves only because the
//     pantry is merged underneath, and what it lacks is named;
//   - ABSENT from our overlay — not ours at all, resolving entirely from the
//     upstream pantry we may not copy (go-zpkg/packages#431).
//
// Collapsing the last two into "not standalone" hides the distinction that
// decides the work: a fragment needs completing, an absence needs writing. The
// tree-wide count cannot see it either, because a project with no recipe of
// ours is not in that tree to be counted — ⚠ an absence that reads as nothing,
// which is the shape this repository keeps meeting.
//
// The judgement is `missingEssentials`, the same function
// `lint --require-standalone` uses, so the two cannot disagree about what a
// fragment is.
func closureStandalone(order []string, overlayDir string, maxFragments int, stdout, stderr io.Writer) int {
	if overlayDir == "" {
		fmt.Fprintln(stderr, "closure: --require-standalone needs --overlay: it asks which of "+
			"these projects have a complete recipe OF OURS, and without an overlay there is no "+
			"tree of ours to ask about")
		return 2
	}
	var fragments, absent, unreadable []string
	standalone := 0
	for _, proj := range order {
		pdir := filepath.Join(overlayDir, "projects", filepath.FromSlash(proj))
		_, doc, err := recipefile.LoadWithDoc(pdir)
		switch {
		// ⛔⛔ BOTH SENTINELS, AND THE SECOND ONE IS WHY THIS COMMENT EXISTS.
		// ErrNoRecipe is returned when the project's DIRECTORY exists and holds
		// none of recipefile.Names; a project with no directory at all comes
		// back as a bare `open …: no such file or directory` from the
		// filesystem. Both mean "we have no recipe for this", and the first
		// run of this flag classified the second as UNREADABLE: 18 of the 20
		// absences in the base-toolchain closure were printed as "cannot be
		// read, counted in neither population above" — an absence reported as
		// something else, by the very check written to stop that.
		case errors.Is(err, recipefile.ErrNoRecipe), errors.Is(err, fs.ErrNotExist):
			absent = append(absent, "  "+proj)
		case err != nil:
			// ⚠ NOT folded into either population. A recipe that EXISTS and
			// cannot be parsed is neither ours-and-complete nor absent, and
			// counting it as either would be a verdict about a file nothing has
			// read. This arm is now only that: a real file that will not load.
			unreadable = append(unreadable, fmt.Sprintf("  %s: %v", proj, err))
		default:
			if miss := missingEssentials(doc); len(miss) > 0 {
				fragments = append(fragments, fmt.Sprintf("  %s: states no %s",
					proj, strings.Join(miss, ", no ")))
			} else {
				standalone++
			}
		}
	}

	// ⛔ THE DENOMINATOR IS PRINTED WITH EVERY NUMERATOR. A count of fragments
	// with no total cannot be told from a walk that read nothing, which is how
	// a scan that could not read once reported a clean zero here.
	fmt.Fprintf(stdout, "closure: %d project(s); %d standalone in the overlay, %d fragment(s), "+
		"%d absent from it", len(order), standalone, len(fragments), len(absent))
	if len(unreadable) > 0 {
		fmt.Fprintf(stdout, ", %d unreadable", len(unreadable))
	}
	fmt.Fprintln(stdout)

	if len(fragments) > 0 {
		sort.Strings(fragments)
		fmt.Fprintf(stdout, "\n%d fragment(s) — ours, and resolving only because the pantry is "+
			"merged underneath; each needs the named keys written:\n", len(fragments))
		fmt.Fprintln(stdout, strings.Join(fragments, "\n"))
	}
	if len(absent) > 0 {
		sort.Strings(absent)
		fmt.Fprintf(stdout, "\n%d project(s) with NO recipe of ours — this build takes them "+
			"entirely from the upstream pantry, which go-zpkg/packages#431 says we may not "+
			"copy, so each is a recipe still to be written:\n", len(absent))
		fmt.Fprintln(stdout, strings.Join(absent, "\n"))
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		fmt.Fprintf(stderr, "\n%d recipe(s) of ours cannot be read, and are counted in neither "+
			"population above:\n", len(unreadable))
		fmt.Fprintln(stderr, strings.Join(unreadable, "\n"))
		return 1
	}

	// The ratchet, in `lint --max-fragments`'s shape and for its reason: a
	// ceiling nobody lowers stops describing the tree, and then a regression
	// hides in the slack. Only fragments are ratcheted — an ABSENT project is
	// not a regression this repository can cause, since the closure decides
	// which projects appear at all.
	switch {
	case maxFragments < 0:
		if len(fragments) > 0 {
			return 1
		}
	case len(fragments) > maxFragments:
		fmt.Fprintf(stderr, "closure: %d fragment(s) in this closure, and --max-fragments says "+
			"%d\n", len(fragments), maxFragments)
		return 1
	case len(fragments) < maxFragments:
		fmt.Fprintf(stderr, "closure: %d fragment(s) in this closure, and --max-fragments says "+
			"%d: lower it to %d. A ceiling nobody lowers stops describing the closure, and then "+
			"a regression hides in the slack\n", len(fragments), maxFragments, len(fragments))
		return 1
	default:
		fmt.Fprintf(stderr, "closure: at the stated ceiling of %d fragment(s); each recipe "+
			"completed must lower it\n", maxFragments)
	}
	return 0
}
