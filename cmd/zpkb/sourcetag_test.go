package main

import (
	"errors"
	"strings"
	"testing"
)

// Every test that does not care about the tag sees the version unchanged; the
// ones below, and the default's own test, say what they mean.
func init() {
	sourceTag = func(_, _, ver, _, _ string) (string, error) { return ver, nil }
}

// ⛔ The bug (promo-r3, lz4.org 1.11.1): the origin was read under the resolved
// build tag and the download asked for the bare version, which a registry written
// by publish-stage does not hold. The download must carry the resolved tag.
func TestPromotionDownloadsTheTagTheOriginWasReadUnder(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	var asked, resolvedFor string
	old, oldTag := factoryDownload, sourceTag
	t.Cleanup(func() { factoryDownload, sourceTag = old, oldTag })
	sourceTag = func(dist, _, ver, _, _ string) (string, error) {
		resolvedFor = dist + " " + ver
		return ver + "-hdeadbeef", nil
	}
	factoryDownload = func(_, ver, _, _ string) ([]byte, string, error) {
		asked = ver
		return r.tarball, ".tar.gz", nil
	}
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin")
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
	}
	if asked != "1.0-hdeadbeef" {
		t.Errorf("the download asked for %q, want the resolved build tag", asked)
	}
	if resolvedFor != mirrorSeed+" 1.0" {
		t.Errorf("resolved %q", resolvedFor)
	}
}

// A tag that cannot be resolved fails the project at the fetch, before any
// download, and says why.
func TestPromotionFailsWhenTheSourceTagCannotBeResolved(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	oldTag := sourceTag
	t.Cleanup(func() { sourceTag = oldTag })
	sourceTag = func(_, _, _, _, _ string) (string, error) { return "", errors.New("two builds") }
	downloaded := false
	factoryDownload = func(_, _, _, _ string) ([]byte, string, error) {
		downloaded = true
		return r.tarball, ".tar.gz", nil
	}
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin")
	if code == 0 || downloaded || !strings.Contains(r.h.out.String(), "FETCH FAIL lib.org 1.0: two builds") {
		t.Errorf("code=%d downloaded=%v\n%s", code, downloaded, r.h.out.String())
	}
}

// Without --require-origin nothing resolves: a mirror that is not a promotion
// keeps asking for the version it was given.
func TestAPlainMirrorDoesNotResolveASourceTag(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	oldTag := sourceTag
	t.Cleanup(func() { sourceTag = oldTag })
	sourceTag = func(_, _, _, _, _ string) (string, error) {
		t.Error("a source tag was resolved without --require-origin")
		return "", errors.New("no")
	}
	r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist, "--mirror-from", mirrorSeed)
}

// The default seam resolves against a real client: an unreachable registry is an
// error, never the bare version.
func TestTheDefaultSourceTagRefusesAnUnreachableRegistry(t *testing.T) {
	if tag, err := defaultSourceTag("oci://127.0.0.1:1/seed", "lz4.org", "1.10.0", "linux", "x86-64"); err == nil {
		t.Errorf("an unreachable registry resolved to %q", tag)
	}
	if tag, err := defaultSourceTag("not a registry ::", "lz4.org", "1.10.0", "linux", "x86-64"); err == nil {
		t.Errorf("a malformed registry resolved to %q", tag)
	}
}

// Package-level variables are initialised before init() replaces the seam.
var defaultSourceTag = sourceTag
