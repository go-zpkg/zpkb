package main

import (
	"errors"
	"testing"

	"github.com/go-zpkg/artifact"
)

const pkgxSeed = "oci://ghcr.io/go-pkgx/packages"

// restoreDist puts artifact's dist state back, INCLUDING the promotion-source
// allowance a promotion grants (SetPromotionSource("") clears it).
func restoreDist(t *testing.T) {
	t.Helper()
	b, x := artifact.DistBase, artifact.DistExtra
	t.Cleanup(func() {
		artifact.SetPromotionSource("")
		artifact.DistBase, artifact.DistExtra = b, x
	})
	artifact.SetPromotionSource("")
}

// ⛔ go-pkgx is closed to everything but the source of a PROMOTION. Both halves
// are asserted: a promotion reads it (the 25-package toolchain promotion died
// at the versions step on this refusal), and a plain mirror or a dependency
// still cannot.
func TestAPromotionMayReadAGoPkgxSource(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	restoreDist(t)
	if err := setUpstreamDist(pkgxSeed, true); err != nil {
		t.Fatalf("setUpstreamDist: %v", err)
	}
	if err := artifact.ValidateDist(); err != nil {
		t.Fatalf("a promotion cannot read its go-pkgx source: %v", err)
	}
}

func TestAPlainMirrorStillCannotReadGoPkgx(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	restoreDist(t)
	if err := setUpstreamDist(pkgxSeed, false); err != nil {
		t.Fatalf("setUpstreamDist: %v", err)
	}
	if err := artifact.ValidateDist(); !errors.Is(err, artifact.ErrClosedDistRegistry) {
		t.Fatalf("a mirror that is not a promotion read go-pkgx: %v", err)
	}
}

func TestAPromotionWithVerificationOffIsRefusedForGoPkgx(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	restoreDist(t)
	artifact.DistBase = pkgxSeed
	if err := setUpstreamDist(pkgxSeed, true); err == nil {
		t.Fatal("a promotion with ZPKG_VERIFY=0 was allowed to read go-pkgx unverified")
	}
	if err := artifact.ValidateDist(); !errors.Is(err, artifact.ErrClosedDistRegistry) {
		t.Fatalf("the refused promotion left go-pkgx readable: %v", err)
	}
}
