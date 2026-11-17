package config

import (
	"strings"
	"testing"
)

// TestCheckRetiredEnvNamesEveryOne: each retired variable is refused, and the
// message names the one to use instead.
//
// Table-driven over RetiredEnv itself rather than over a list written here: a
// name added to the map without a test is the gap this check exists to close,
// and a second list would be free to drift from the first — the defect
// go-zpkg/zpkb#494 was filed for.
func TestCheckRetiredEnvNamesEveryOne(t *testing.T) {
	if len(RetiredEnv) == 0 {
		t.Fatal("no retired names: this test measured nothing")
	}
	for old, now := range RetiredEnv {
		err := CheckRetiredEnv(func(k string) (string, bool) {
			return "/somewhere", k == old
		})
		if err == nil {
			t.Errorf("%s is retired and was accepted", old)
			continue
		}
		if !strings.Contains(err.Error(), old) {
			t.Errorf("%s: the message does not name the variable: %v", old, err)
		}
		if !strings.Contains(err.Error(), now) {
			t.Errorf("%s: the message does not name its replacement %s: %v", old, now, err)
		}
	}
}

// ⛔⛔ A SET-BUT-EMPTY RETIRED VARIABLE IS STILL SET, and this is the case a
// `os.Getenv(x) != ""` implementation would miss. A workflow carrying
// `ZPKG_PANTRY_OVERLAY: ""` has been EDITED to name the old variable; it is
// exactly the file that needs changing, and saying nothing about it would hide
// the one place the rename has still to reach.
func TestCheckRetiredEnvRefusesASetButEmptyOne(t *testing.T) {
	err := CheckRetiredEnv(func(k string) (string, bool) {
		return "", k == "ZPKG_PANTRY_OVERLAY"
	})
	if err == nil {
		t.Fatal("a set-but-empty retired variable must still be refused")
	}
	if !strings.Contains(err.Error(), "ZPKG_PANTRY_OVERLAY") {
		t.Errorf("the message does not name it: %v", err)
	}
}

// Nothing retired set: no error, and no complaint about the live names either.
func TestCheckRetiredEnvAcceptsTheLiveNames(t *testing.T) {
	live := map[string]bool{
		"ZPKG_RECIPES": true, "ZPKG_RECIPES_OVERLAY": true, "ZPKG_RECIPE_DIR": true,
		"ZPKB_RECIPES_CORPUS": true, "RECIPE_DIR": true, "RECIPE_OVERLAY_DIR": true,
		"ZPKG_DIR": true, "ZPKG_DIST": true,
	}
	if err := CheckRetiredEnv(func(k string) (string, bool) {
		return "/x", live[k]
	}); err != nil {
		t.Errorf("the live names must pass: %v", err)
	}
}

// ⛔ ALL OF THEM, NOT THE FIRST. A caller exporting three retired variables
// would otherwise fix one, rerun, meet the next, and do it three times — each
// run believing it was the last. That is the shape of the sweeps this rename is
// trying to end, so the message is a list.
func TestCheckRetiredEnvReportsAllOfThem(t *testing.T) {
	set := map[string]bool{"ZPKG_PANTRY": true, "ZPKG_PANTRY_DIR": true, "PANTRY": true}
	err := CheckRetiredEnv(func(k string) (string, bool) { return "/x", set[k] })
	if err == nil {
		t.Fatal("three retired variables were accepted")
	}
	for k := range set {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("the message does not name %s: %v", k, err)
		}
	}
	if !strings.Contains(err.Error(), "3 variable(s)") {
		t.Errorf("the message does not count them: %v", err)
	}
}

// ⛔⛔ NO REPLACEMENT MAY ITSELF BE RETIRED, which is the invariant the fleet
// learned the expensive way: the prefix went BK_ → ZBK_ → ZPKB_, and a recipe
// left on the MIDDLE spelling read an unset variable in silence for a week
// (go-zpkg/recipes#138). A tombstone pointing at another tombstone would send
// the next reader to a name that is also dead.
func TestNoRetiredNamePointsAtAnotherRetiredName(t *testing.T) {
	for old, now := range RetiredEnv {
		if _, dead := RetiredEnv[now]; dead {
			t.Errorf("%s points at %s, which is itself retired", old, now)
		}
	}
}

// The nil lookup is the production path: it must read the real environment
// rather than panic. Nothing retired is set in a test process, so this also
// asserts the default is quiet.
func TestCheckRetiredEnvDefaultsToTheProcessEnvironment(t *testing.T) {
	t.Setenv("ZPKG_PANTRY_OVERLAY", "/x")
	err := CheckRetiredEnv(nil)
	if err == nil {
		t.Fatal("with nil the real environment is read, and this one is poisoned")
	}
	if !strings.Contains(err.Error(), "ZPKG_PANTRY_OVERLAY") {
		t.Errorf("the message does not name it: %v", err)
	}
}
