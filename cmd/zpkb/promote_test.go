package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// promoteFactory is a factory configured the way a promotion runs: copying
// from the seed's registry into the production one.
func promoteFactory() *factory {
	return &factory{
		osn: "linux", arch: "s390x", platform: "linux/s390x",
		dist:          "oci://ghcr.io/go-zpkg/packages",
		mirror:        "oci://127.0.0.1:5000/seed",
		requireOrigin: true,
	}
}

// sovereignSource is what a build that measured itself sovereign records.
var sovereignSource = provOrigin{Bootstrap: "0", Sovereign: "1", Dist: "oci://127.0.0.1:5000/seed"}

// ⛔ TestPromotionRefusesABootstrapArtifact is the rule the whole feature
// exists for: generations 0 and 1 publish to a throwaway registry because
// their artifacts were driven by the host's compiler, and this is what stops
// one of them reaching production under our signature.
func TestPromotionRefusesABootstrapArtifact(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, provOrigin{Bootstrap: "1", Sovereign: "0", Dist: "oci://127.0.0.1:5000/seed"}, nil)
	_, err := promoteFactory().promotableOrigin("lz4.org", "1.10.0")
	if err == nil {
		t.Fatal("a --bootstrap artifact was accepted for promotion")
	}
	for _, want := range []string{"not promotable", "sovereign"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// ⛔ TestPromotionRefusesASilentProvenance. Every artifact published before bk
// recorded an origin is in this state, and so is every mirrored one. Silence
// is the commonest answer, so it is the one most likely to be waved through.
func TestPromotionRefusesASilentProvenance(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, provOrigin{}, nil)
	if _, err := promoteFactory().promotableOrigin("lz4.org", "1.10.0"); err == nil {
		t.Fatal("an artifact whose provenance says nothing was accepted for promotion")
	}
}

// ⛔ TestPromotionRefusesAnOldBootstrapZeroArtifact is finding 5: bootstrap=0
// says only that a flag was absent, and a build with the runner's own gcc
// satisfies it. Such an artifact, correctly signed and with a matching
// provenance, has no sovereign fact in its signature and is refused.
func TestPromotionRefusesAnOldBootstrapZeroArtifact(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, provOrigin{Bootstrap: "0", Dist: "oci://127.0.0.1:5000/seed"}, nil)
	_, err := promoteFactory().promotableOrigin("lz4.org", "1.10.0")
	if err == nil {
		t.Fatal("an artifact that only says bootstrap=0 was accepted for promotion")
	}
	if !strings.Contains(err.Error(), "sovereign") {
		t.Errorf("the refusal does not name the missing fact: %v", err)
	}
}

// ⛔ TestPromotionDistinguishesCannotAskFromNo. "I could not reach the
// registry" and "the answer was no" must not land in the same branch: one is
// a verdict, the other is an outage, and a gate that folds them together
// turns every network blip into a permanent judgement about an artifact.
func TestPromotionDistinguishesCannotAskFromNo(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, provOrigin{}, errors.New("dial tcp 127.0.0.1:5000: connection refused"))
	_, err := promoteFactory().promotableOrigin("lz4.org", "1.10.0")
	if err == nil {
		t.Fatal("an unreachable source registry was accepted")
	}
	if !strings.Contains(err.Error(), "cannot read or authenticate the source provenance") {
		t.Errorf("the error does not say the source could not be read: %v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:5000") {
		t.Errorf("the error does not name the registry it failed to read: %v", err)
	}
	// And it must not read as a verdict about the artifact.
	if strings.Contains(err.Error(), "not promotable") {
		t.Errorf("an outage was reported as a judgement: %v", err)
	}
}

// ⛔ TestPromotionCarriesTheVerdictRatherThanRestatingIt. The facts belong to
// the BUILD: copying an artefact between registries does not change what
// built it. Re-stating them as ours would launder a verdict this run did not
// make — and would also lose `inputs-from`, which is the only record that the
// artifact was built against the seed and not against ghcr.
func TestPromotionCarriesTheVerdictRatherThanRestatingIt(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, sovereignSource, nil)

	got, err := promoteFactory().promotableOrigin("lz4.org", "1.10.0")
	if err != nil {
		t.Fatalf("a sovereign artifact was refused: %v", err)
	}
	want := sovereignSource
	want.Digest = testDigest
	if !reflect.DeepEqual(got, want) {
		t.Errorf("origin = %+v, want the source's %+v carried through", got, want)
	}
	// Specifically: NOT rewritten to the destination registry.
	if got.Dist == "oci://ghcr.io/go-zpkg/packages" {
		t.Error("inputs-from was rewritten to the destination, losing the fact that the inputs came from the seed")
	}
}

// TestRequireOriginNeedsAMirrorSource: a gate the operator believes ran, over
// a source that does not exist, is worse than no gate. Without --mirror-from
// there is no source provenance to read at all.
func TestRequireOriginNeedsAMirrorSource(t *testing.T) {
	code, _, errb := run2(t, "factory", "--require-origin", "--platform", "linux/s390x", "lz4.org")
	if code != 2 {
		t.Fatalf("bk factory --require-origin without --mirror-from = %d, want 2", code)
	}
	if !strings.Contains(errb, "--mirror-from") {
		t.Errorf("the refusal does not name the missing flag: %q", errb)
	}
}

// promoteRun drives a whole `--mirror-from --require-origin` run against a
// source whose provenance states `origin`, and reports what was published.
func promoteRun(t *testing.T, origin provOrigin, srcErr error) (code int, h *factoryHarness) {
	t.Helper()
	t.Setenv("ZPKG_VERIFY", "1")
	h = newFactoryHarness(t)
	prevDown, prevVers, prevDist := factoryDownload, factoryUpstreamVersions, artifact.DistBase
	t.Cleanup(func() {
		factoryDownload, factoryUpstreamVersions, artifact.DistBase = prevDown, prevVers, prevDist
	})
	factoryUpstreamVersions = func(string, string, string) ([]artifact.Ver, error) {
		return []artifact.Ver{artifact.ParseVer("1.0")}, nil
	}
	factoryDownload = func(string, string, string, string) ([]byte, string, error) {
		return testTarball, artifact.ExtTarXz, nil
	}
	stubVerified(t, origin, srcErr)

	code = h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--mirror-from", "oci://127.0.0.1:5000/seed", "--require-origin")
	return code, h
}

// ⛔ TestAPromotionRunPublishesNothingItCannotVouchFor, end to end. The unit
// test above proves the rule; this proves the rule is WIRED — a gate that
// computes the right verdict and publishes anyway is the defect it exists to
// prevent, and from inside promotableOrigin the two look identical.
func TestAPromotionRunPublishesNothingItCannotVouchFor(t *testing.T) {
	for _, c := range []struct {
		name   string
		origin provOrigin
		srcErr error
		reason string
	}{
		{"bootstrap", provOrigin{Bootstrap: "1", Sovereign: "0", Dist: "oci://127.0.0.1:5000/seed"}, nil, "sovereign"},
		{"silent", provOrigin{}, nil, "sovereign"},
		{"old bootstrap=0 only", provOrigin{Bootstrap: "0", Dist: "oci://127.0.0.1:5000/seed"}, nil, "sovereign"},
		{"unreachable source", provOrigin{}, errors.New("connection refused"), "cannot read or authenticate the source provenance"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, h := promoteRun(t, c.origin, c.srcErr)
			if len(h.published) != 0 {
				t.Errorf("%d artifact(s) were published despite %s", len(h.published), c.name)
			}
			// ⛔ The REASON, from the run's own failure record, not from
			// stderr. Nothing published is the right outcome for a dozen
			// wrong reasons — the first draft of this test read stderr and
			// "passed" its publish assertion while the run had actually
			// skipped the project for want of a recipe file. A refusal has
			// to be attributed or it is not evidence.
			detail := h.detailFile(t)
			if !strings.Contains(detail, c.reason) {
				t.Errorf("the failure record does not say why it refused (%q):\n%s", c.reason, detail)
			}
			if !strings.Contains(detail, "origin") {
				t.Errorf("the failure is not attributed to the origin stage:\n%s", detail)
			}
		})
	}
}

// TestAPromotionRunPublishesASovereignArtifact: the positive control. Without
// it, every test above would pass on a gate that refuses everything.
func TestAPromotionRunPublishesASovereignArtifact(t *testing.T) {
	code, h := promoteRun(t, sovereignSource, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if len(h.published) == 0 {
		t.Fatal("a sovereign artifact was not promoted, so the gate refuses everything")
	}
}

// ⛔ TestAPromotionRefusesBytesOtherThanTheOnesVouchedFor: the origin was
// authenticated for one digest, and a registry may answer the download with
// another tarball. It is the call that republishes under our key.
func TestAPromotionRefusesBytesOtherThanTheOnesVouchedFor(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	h := newFactoryHarness(t)
	prevDown, prevVers, prevDist := factoryDownload, factoryUpstreamVersions, artifact.DistBase
	t.Cleanup(func() {
		factoryDownload, factoryUpstreamVersions, artifact.DistBase = prevDown, prevVers, prevDist
	})
	factoryUpstreamVersions = func(string, string, string) ([]artifact.Ver, error) {
		return []artifact.Ver{artifact.ParseVer("1.0")}, nil
	}
	factoryDownload = func(string, string, string, string) ([]byte, string, error) {
		return []byte("a forged tarball"), artifact.ExtTarXz, nil
	}
	stubVerified(t, sovereignSource, nil)
	h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--mirror-from", "oci://127.0.0.1:5000/seed", "--require-origin")
	if len(h.published) != 0 {
		t.Fatal("a tarball other than the authenticated one was republished")
	}
	if d := h.detailFile(t); !strings.Contains(d, "whose origin was authenticated") {
		t.Errorf("the refusal does not say why:\n%s", d)
	}
}

// ⛔ TestRequireOriginRefusesWhatCannotBeAuthenticated: a non-OCI mirror has no
// signatures, and ZPKG_VERIFY=0 reads them without checking. Both are refused
// before anything runs, with exit 2, and neither switches verification off.
func TestRequireOriginRefusesWhatCannotBeAuthenticated(t *testing.T) {
	t.Run("non-oci mirror", func(t *testing.T) {
		t.Setenv("ZPKG_VERIFY", "1")
		h := newFactoryHarness(t)
		code := h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
			"--require-origin", "--mirror-from", "https://dist.example")
		if code != 2 || !strings.Contains(h.errb.String(), "oci://") || len(h.published) != 0 {
			t.Errorf("code = %d, stderr = %q", code, h.errb.String())
		}
	})
	t.Run("verification off", func(t *testing.T) {
		t.Setenv("ZPKG_VERIFY", "0")
		h := newFactoryHarness(t)
		code := h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
			"--require-origin", "--mirror-from", "oci://127.0.0.1:5000/seed")
		if code != 2 || !strings.Contains(h.errb.String(), "ZPKG_VERIFY") || len(h.published) != 0 {
			t.Errorf("code = %d, stderr = %q", code, h.errb.String())
		}
	})
}
