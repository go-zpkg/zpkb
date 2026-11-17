package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// RetiredEnv maps each environment variable this builder no longer reads to the
// one that replaced it.
//
// ⛔⛔ IT EXISTS BECAUSE THE FAILURE IT PREVENTS IS SILENT. A shell expands an
// unset variable to the empty string and exits 0, so a caller still exporting
// `ZPKG_PANTRY_OVERLAY` after the rename does not fail — it builds WITHOUT the
// overlay and says nothing. That is exactly the defect go-zpkg/zpkb#494's lint
// gate was written for, measured four times over three sweeps, and this is the
// same lesson applied to the OTHER side of the contract: that gate catches a
// recipe READING a name nothing exports, and this catches a caller EXPORTING a
// name nothing reads.
//
// ⛔ IT IS NOT AN ALIAS, and the difference is the whole point. An alias would
// accept the old name and keep working, which means every document explains two
// spellings forever and the rename never finishes — the argument target.go
// already makes about BREWKIT_TARGET. A tombstone accepts nothing: it REFUSES,
// names the replacement, and disappears from the code once no caller trips it.
//
// ⚠ The pairs are one-way on purpose. `ZPKG_PANTRY_PATH` has no replacement of
// its own because it was already the older spelling of `ZPKG_PANTRY_DIR`; both
// retired together and both point at `ZPKG_RECIPE_DIR`.
var RetiredEnv = map[string]string{
	"ZPKG_PANTRY":         "ZPKG_RECIPES",
	"ZPKG_PANTRY_OVERLAY": "ZPKG_RECIPES_OVERLAY",
	"ZPKG_PANTRY_DIR":     "ZPKG_RECIPE_DIR",
	"ZPKG_PANTRY_PATH":    "ZPKG_RECIPE_DIR",
	"ZPKB_PANTRY_CORPUS":  "ZPKB_RECIPES_CORPUS",
	"PANTRY":              "RECIPE_DIR",
	"PANTRY_OVERLAY_DIR":  "RECIPE_OVERLAY_DIR",
}

// CheckRetiredEnv returns an error naming every retired variable the
// environment still sets, and what to use instead.
//
// It reports ALL of them rather than the first: a caller that exports three of
// these would otherwise fix one, rerun, and meet the next — three times over,
// each time believing it was the last.
//
// ⚠ Set-but-EMPTY counts as set. A workflow writing `ZPKG_PANTRY_OVERLAY: ""`
// has still been edited to name the old variable, and leaving it unreported
// would hide precisely the file that needs changing. `os.LookupEnv` is what
// distinguishes that from absent; `os.Getenv` could not.
func CheckRetiredEnv(lookup func(string) (string, bool)) error {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var found []string
	for old := range RetiredEnv {
		if _, ok := lookup(old); ok {
			found = append(found, old)
		}
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	var b strings.Builder
	fmt.Fprintf(&b, "this environment sets %d variable(s) this builder no longer reads, "+
		"and an unread variable is SILENT — the build would run without what it names:\n", len(found))
	for _, old := range found {
		fmt.Fprintf(&b, "  %s is now %s\n", old, RetiredEnv[old])
	}
	b.WriteString("The `pantry` vocabulary was pkgx's; go-zpkg/pantry-overlay is go-zpkg/recipes now.")
	return fmt.Errorf("%s", b.String())
}
