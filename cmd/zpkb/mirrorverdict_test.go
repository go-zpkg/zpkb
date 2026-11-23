package main

import (
	"strings"
	"testing"
)

// ⛔ A MIRROR COMPILES NOTHING. promo-r1 printed
//
//	sovereign: no (--libc zpkx was not selected) — these artifacts cannot be promoted
//
// on a run that was about to stage a verified sovereign artifact. The message
// measured the machine, which is irrelevant to a copy; the staged record carries
// the SOURCE's verdict, and this pins both halves.
func TestAMirrorCarriesTheSourcesSovereignVerdictAndSaysSo(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin")
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
	}
	out := r.h.out.String()
	if strings.Contains(out, "cannot be promoted") || strings.Contains(out, "sovereign: no") {
		t.Errorf("a mirror run says its artifacts are not sovereign:\n%s", out)
	}
	if !strings.Contains(out, "sovereign: carried from each source artifact's signed claim") {
		t.Errorf("the mirror run does not say where the verdict comes from:\n%s", out)
	}
	es := planEntries(readPlan(t, r.h.artifacts))
	if len(es) != 1 {
		t.Fatalf("plan has %d entries, want 1", len(es))
	}
	e := es[0].(map[string]any)
	if e["sovereign"] != "1" || e["bootstrap"] != "0" {
		t.Errorf("staged record sovereign=%v bootstrap=%v, want the source's 1 and 0", e["sovereign"], e["bootstrap"])
	}
}
