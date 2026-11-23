package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
)

// seedKey is a throwaway key standing for the seed registry's signing key, and a
// signature of its making over `tarball`.
func seedKey(t *testing.T) (entry string, digest string, att artifact.Attestation) {
	t.Helper()
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tarball := stageTarball(t, "seed")
	refs, err := buildReferrers("lz4.org", "1.11.1", "linux", "x86-64", tarball, build.SourceRef{}, nil, time.Unix(0, 0).UTC(), kp, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	r := refs[2]
	return "seed-b6:" + kp.PublicKeyString(), digestOf(tarball), artifact.Attestation{
		Payload: r.Blob,
		Sig:     r.Annotations[artifact.CosignSignatureAnnotation],
		KeyID:   r.Annotations[artifact.SignerKeyIDAnnotation],
	}
}

func signersOf(t *testing.T, digest string, att artifact.Attestation) []string {
	t.Helper()
	ts, err := artifact.LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	names, _, _ := ts.Count(digest, []artifact.Attestation{att})
	return names
}

// ⛔ THE FAILURE OF promo-r2: a seed signed with a key clients must not trust
// could not be verified by the promotion. With the key given for the SOURCE it
// verifies; without it, as before, it does not; and the key is gone afterwards.
func TestASourceKeyVerifiesTheSourceAndNothingElse(t *testing.T) {
	entry, digest, att := seedKey(t)
	t.Setenv(artifact.ExtraTrustedKeysEnv, "")
	os.Unsetenv(artifact.ExtraTrustedKeysEnv)

	if got := signersOf(t, digest, att); len(got) != 0 {
		t.Fatalf("control: the seed key is trusted by default: %v", got)
	}
	var inside []string
	if err := underSourceTrust([]string{entry}, func() error {
		inside = signersOf(t, digest, att)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(inside) != 1 || inside[0] != "seed-b6" {
		t.Errorf("inside the source read the seed key is not believed: %v", inside)
	}
	if got := signersOf(t, digest, att); len(got) != 0 {
		t.Errorf("after the read the seed key is still believed (a non-mirror install would trust it): %v", got)
	}
	if v, ok := os.LookupEnv(artifact.ExtraTrustedKeysEnv); ok {
		t.Errorf("the variable was left behind: %q", v)
	}
}

func TestTheSourceKeyJoinsTheOperatorsExtraKeysAndTheyAreRestored(t *testing.T) {
	entry, digest, att := seedKey(t)
	other, _, _ := seedKey(t)
	other = strings.Replace(other, "seed-b6", "operator", 1)
	t.Setenv(artifact.ExtraTrustedKeysEnv, other)
	err := underSourceTrust([]string{entry}, func() error {
		got := os.Getenv(artifact.ExtraTrustedKeysEnv)
		if !strings.Contains(got, other) || !strings.Contains(got, entry) {
			t.Errorf("inside, extra keys = %q: want the operator's and the source's", got)
		}
		if len(signersOf(t, digest, att)) != 1 {
			t.Error("inside, the seed key is not believed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(artifact.ExtraTrustedKeysEnv); got != other {
		t.Errorf("restored to %q, want the operator's own %q", got, other)
	}
}

func TestASourceReadThatFailsStillRestoresAndReturnsTheError(t *testing.T) {
	entry, _, _ := seedKey(t)
	os.Unsetenv(artifact.ExtraTrustedKeysEnv)
	boom := errors.New("boom")
	if err := underSourceTrust([]string{entry}, func() error { return boom }); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if _, ok := os.LookupEnv(artifact.ExtraTrustedKeysEnv); ok {
		t.Error("the variable was left behind after a failed read")
	}
}

func TestNoSourceKeyTouchesNothing(t *testing.T) {
	t.Setenv(artifact.ExtraTrustedKeysEnv, "x")
	if err := underSourceTrust(nil, func() error {
		if os.Getenv(artifact.ExtraTrustedKeysEnv) != "x" {
			t.Error("changed with no key")
		}
		// No key, no scope: the read must not queue behind another's.
		if !sourceTrustMu.TryLock() {
			t.Error("a read with no key took the lock")
		} else {
			sourceTrustMu.Unlock()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestParseSourceTrust(t *testing.T) {
	entry, _, _ := seedKey(t)
	if got, err := parseSourceTrust("  " + entry + "  "); err != nil || len(got) != 1 || got[0] != entry {
		t.Errorf("one key: %v %v", got, err)
	}
	if got, err := parseSourceTrust(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
	if _, err := parseSourceTrust("not-a-key"); err == nil || strings.Contains(err.Error(), "not-a-key") {
		t.Errorf("malformed accepted: %v", err)
	}
	many := strings.TrimSpace(strings.Repeat(entry+" ", maxSourceTrustedKeys+1))
	if _, err := parseSourceTrust(many); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("%d keys accepted: %v", maxSourceTrustedKeys+1, err)
	}
	ok := strings.TrimSpace(strings.Repeat(entry+" ", maxSourceTrustedKeys))
	if _, err := parseSourceTrust(ok); err != nil {
		t.Errorf("%d keys refused: %v", maxSourceTrustedKeys, err)
	}
}

// The flag is read only when a promotion verifies its source, so a run that
// could not use it refuses it (a gate that guards nothing), a malformed one is
// refused before anything is paid for, and the key is the SOURCE read's alone.
func TestSourceTrustFlag(t *testing.T) {
	entry, _, _ := seedKey(t)
	t.Run("refused without a promotion", func(t *testing.T) {
		h := newFactoryHarness(t)
		for _, extra := range [][]string{
			{"--recipes", "lib.org", "--source-trust", entry},
			{"--recipes", "lib.org", "--source-trust", entry, "--mirror-from", mirrorSeed},
		} {
			if code := h.run(t, extra...); code != 2 || !strings.Contains(h.errb.String(), "--source-trust") {
				t.Errorf("%v: code=%d %s", extra, code, h.errb.String())
			}
		}
	})
	t.Run("a malformed key is refused and not echoed", func(t *testing.T) {
		h := newFactoryHarness(t)
		code := h.run(t, "--recipes", "lib.org", "--source-trust", "garbage-RWsecretlooking",
			"--mirror-from", mirrorSeed, "--require-origin")
		if code != 2 || !strings.Contains(h.errb.String(), "--source-trust") || strings.Contains(h.errb.String(), "RWsecretlooking") {
			t.Errorf("code=%d %s", code, h.errb.String())
		}
	})
	t.Run("a promotion reads its source under the key, then forgets it", func(t *testing.T) {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		var seen []string
		inner := sourceVerified
		sourceVerified = func(a, b, c, d, e string) (string, [][]byte, []artifact.Referrer, error) {
			seen = append([]string(nil), sourceTrust...)
			return inner(a, b, c, d, e)
		}
		t.Cleanup(func() { sourceVerified = inner })
		code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
			"--mirror-from", mirrorSeed, "--require-origin", "--source-trust", entry)
		if code != 0 {
			t.Fatalf("code=%d\n%s", code, r.h.errb.String())
		}
		if len(seen) != 1 || seen[0] != entry {
			t.Errorf("the source read saw keys %v", seen)
		}
		if len(sourceTrust) != 0 {
			t.Errorf("the key outlived the run: %v", sourceTrust)
		}
		if strings.Contains(r.h.out.String()+r.h.errb.String(), entry) {
			t.Error("the key was printed")
		}
		plan, err := os.ReadFile(r.h.artifacts + "/" + stagePlanName)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(plan), strings.TrimPrefix(entry, "seed-b6:")) {
			t.Error("the stage plan records the source key as trust")
		}
	})
}

// The default sourceVerified is the one place the keys are applied.
func TestTheDefaultSourceReadAppliesTheKeys(t *testing.T) {
	entry, _, _ := seedKey(t)
	old := sourceTrust
	t.Cleanup(func() { sourceTrust = old })
	sourceTrust = []string{entry}
	// An unreachable registry: the read fails, but only after resolving trust.
	_, _, _, err := sourceVerified("oci://127.0.0.1:1/seed", "lz4.org", "1.10.0", "linux", "x86-64")
	if err == nil {
		t.Fatal("an unreachable registry answered")
	}
	if _, ok := os.LookupEnv(artifact.ExtraTrustedKeysEnv); ok && os.Getenv(artifact.ExtraTrustedKeysEnv) == entry {
		t.Error("the key was left in the environment")
	}
}

// ⛔ promo-r4: the origin read believed --source-trust, then the download, which
// verifies the signature too, did not: "signed by no trusted key". The download
// must run with the source keys in the trust environment, and only for its own
// duration.
func TestPromotionDownloadsUnderTheSourceKeys(t *testing.T) {
	entry, _, _ := seedKey(t)
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	var env string
	old := factoryDownload
	t.Cleanup(func() { factoryDownload = old })
	factoryDownload = func(_, _, _, _ string) ([]byte, string, error) {
		env = artifact.Env(artifact.ExtraTrustedKeysEnv)
		return r.tarball, ".tar.gz", nil
	}
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin", "--source-trust", entry)
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, r.h.errb.String())
	}
	if !strings.Contains(env, entry) {
		t.Errorf("the download verified under %q, without the source key", env)
	}
	if got := artifact.Env(artifact.ExtraTrustedKeysEnv); strings.Contains(got, entry) {
		t.Errorf("the source key outlived the download: %q", got)
	}
}
