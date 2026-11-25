package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The positive control for every refusal below: an artifact signed by the
// production path as seed-built answers with the ledger digest of the claim.
func TestAVerifiedSeedClaimIsReturned(t *testing.T) {
	o := seededOrigin()
	d, p, r := signedFixture(t, o)
	for _, want := range []string{"", o.Seed, "sha256:" + o.Seed} {
		got, err := authenticatedSeed(d, p, r, want)
		if err != nil || got != o.Seed {
			t.Errorf("want %q: seed = %q, %v; expected %q", want, got, err, o.Seed)
		}
	}
}

func TestAnArtifactWithoutASeedClaimIsNotSeeded(t *testing.T) {
	d, p, r := signedFixture(t, sovereignSource)
	if _, err := authenticatedSeed(d, p, r, ""); err == nil || !strings.Contains(err.Error(), "no seed claim") {
		t.Fatalf("an unseeded artifact passed --seeded: %v", err)
	}
}

func TestAClaimForAnotherLedgerIsRefused(t *testing.T) {
	d, p, r := signedFixture(t, seededOrigin())
	_, err := authenticatedSeed(d, p, r, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "not the expected") {
		t.Fatalf("a claim for another ledger was accepted: %v", err)
	}
}

// What the registry serves cannot answer in the signature's place.
func TestTheSeedClaimNeedsASignatureAndItsProvenance(t *testing.T) {
	o := seededOrigin()
	d, p, r := signedFixture(t, o)
	if _, err := authenticatedSeed(d, nil, r, ""); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Errorf("no signature: %v", err)
	}
	if _, err := authenticatedSeed("", p, r, ""); err == nil || !strings.Contains(err.Error(), "digest is unknown") {
		t.Errorf("unknown digest: %v", err)
	}
	if _, err := authenticatedSeed(d, p, nil, ""); err != errNoProvenance {
		t.Errorf("no provenance: %v", err)
	}
	// Another artifact's claim and provenance, under this digest.
	d2, p2, r2 := signedFixtureFor(t, []byte("another tarball"), o)
	if _, err := authenticatedSeed(d, p2, r2, ""); err == nil || !strings.Contains(err.Error(), "another artifact digest") {
		t.Errorf("a claim about another digest: %v", err)
	}
	// The right signature with another artifact's provenance.
	if _, err := authenticatedSeed(d, p, r2, ""); err == nil || !strings.Contains(err.Error(), "no provenance referrer matches") {
		t.Errorf("a swapped provenance: %v", err)
	}
	// The provenance the signature names, about another artifact.
	if _, err := authenticatedSeed(d2, p2, r, ""); err == nil {
		t.Errorf("a provenance about another artifact: %v", err)
	}
	if _, err := authenticatedSeed(d, [][]byte{[]byte("not json")}, r, ""); err == nil {
		t.Error("an unreadable payload passed")
	}
	// A seed claim with no provenance claim.
	pl, err := originSigning("acme.org/tool:1.2.3", d, originClaims{ManifestDigest: d, Seed: o.Seed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticatedSeed(d, [][]byte{pl}, r, ""); err == nil || !strings.Contains(err.Error(), "no claim about the provenance") {
		t.Errorf("a seed claim without a provenance claim: %v", err)
	}
}

func TestOriginSeededIsSilentOnYesAndRefusesOnNo(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	o := seededOrigin()
	stubVerified(t, o, nil)
	var out, errOut bytes.Buffer
	if code := runOrigin(originArgs("--dist", "oci://x/y", "--seeded", "--seed-ledger-sha256", o.Seed), &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("a seeded artifact: %d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runOrigin(originArgs("--dist", "oci://x/y", "--seeded", "--seed-ledger-sha256", strings.Repeat("1", 64)), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not the expected") {
		t.Errorf("another ledger: %d %q", code, errOut.String())
	}
	stubVerified(t, sovereignSource, nil)
	errOut.Reset()
	if code := runOrigin(originArgs("--dist", "oci://x/y", "--seeded"), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "no seed claim") {
		t.Errorf("an unseeded artifact: %d %q", code, errOut.String())
	}
	// A registry that cannot be authenticated is a refusal too.
	errOut.Reset()
	if code := runOrigin(originArgs("--dist", "https://static.example/dist", "--seeded"), &out, &errOut); code != 1 {
		t.Errorf("an unauthenticated registry: %d %q", code, errOut.String())
	}
	errOut.Reset()
	stubVerified(t, o, errors.New("registry down"))
	if code := runOrigin(originArgs("--dist", "oci://x/y", "--seeded"), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "cannot read or authenticate") {
		t.Errorf("a registry that fails: %d %q", code, errOut.String())
	}
}

func TestOriginSeededRefusesItsContradictions(t *testing.T) {
	for _, args := range [][]string{
		originArgs("--seeded", "--promotable"),
		originArgs("--seed-ledger-sha256", strings.Repeat("a", 64)),
	} {
		var out, errOut bytes.Buffer
		if code := runOrigin(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, %q", args, code, errOut.String())
		}
	}
}
