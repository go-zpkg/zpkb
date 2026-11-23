package main

import (
	"errors"
	"strings"
	"testing"
)

// ⛔ "0 built, 0 skipped, 1 failed" EXITED 0 (go-zpkg/packages run 45140545009),
// so every step above it read green. A promotion fails the run; --strict asks
// the same of any run; the nightly chunk, which names nothing, keeps exit 0.
func TestAFailedProjectFailsThePromotionAndAStrictRun(t *testing.T) {
	failing := func(t *testing.T) *mirrorStageRig {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		factoryDownload = func(string, string, string, string) ([]byte, string, error) {
			return nil, "", errors.New("registry down")
		}
		return r
	}
	t.Run("promotion", func(t *testing.T) {
		r := failing(t)
		code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
			"--mirror-from", mirrorSeed, "--require-origin")
		if code != 1 || !strings.Contains(r.h.errb.String(), "1 failed") {
			t.Errorf("code=%d stderr=%q, want 1 and the count", code, r.h.errb.String())
		}
	})
	t.Run("strict", func(t *testing.T) {
		r := failing(t)
		if code := r.h.run(t, "--strict", "--recipes", "lib.org", "--to", stageDist, "--mirror-from", mirrorSeed); code != 1 {
			t.Errorf("code=%d, want 1", code)
		}
	})
	t.Run("default keeps the best-effort chunk", func(t *testing.T) {
		r := failing(t)
		if code := r.h.run(t, "--recipes", "lib.org", "--to", stageDist, "--mirror-from", mirrorSeed); code != 0 {
			t.Errorf("code=%d, want 0 without --strict", code)
		}
	})
}
