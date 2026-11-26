package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/go-zpkg/artifact"
)

// `zpkb origin --seeded` is the converse of --promotable. A second pass reads
// the first pass's outputs as its build environment, and the first pass was
// built from a SEED: the claim that says so (optSeed) is under the signature,
// so what the second pass reads can be checked to be exactly that — an artifact
// the first pass signed as seed-built, with a ledger digest, about this very
// artifact digest — and not an artifact of unknown origin that happens to sit in
// the same registry.
//
// ⛔ THE ANSWER IS THE SIGNED CLAIM, NEVER THE REFERRER. Like --promotable this
// reads verifiedOrigin's inputs (the signed payloads that vouch for the digest),
// and the unauthenticated provenance is consulted only for the one hash the
// signature names.

// authenticatedSeed returns the ledger digest a verified signature claims for the
// artifact with the given digest. want, when not empty, is the ledger digest the
// caller expects (hex, with or without "sha256:"); a claim for another ledger is
// a refusal, so one pass cannot be fed the artifacts of another.
func authenticatedSeed(digest string, payloads [][]byte, refs []artifact.Referrer, want string) (string, error) {
	if len(payloads) == 0 {
		return "", errors.New("no signature vouches for this artifact")
	}
	sub := strings.TrimPrefix(digest, "sha256:")
	if sub == "" {
		return "", errors.New("the artifact digest is unknown")
	}
	want = strings.TrimPrefix(want, "sha256:")
	var prov [][]byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			prov = append(prov, r.Blob)
		}
	}
	if len(prov) == 0 {
		return "", errNoProvenance
	}
	var first error
	note := func(err error) {
		if first == nil {
			first = err
		}
	}
	for _, pl := range payloads {
		c, err := parseOriginClaims(pl)
		if err != nil {
			note(err)
			continue
		}
		switch {
		case c.ManifestDigest != digest:
			note(errors.New("a signed claim is about another artifact digest"))
			continue
		case c.Seed == "":
			note(errors.New("the signature carries no seed claim: this artifact was not built from a seed"))
			continue
		case want != "" && c.Seed != want:
			note(fmt.Errorf("the signed seed ledger is sha256:%s, not the expected sha256:%s", c.Seed, want))
			continue
		case c.Provenance == "":
			note(errors.New("the signature carries no claim about the provenance"))
			continue
		}
		for _, raw := range prov {
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != c.Provenance {
				continue
			}
			if _, err := provenanceAbout(raw, sub); err != nil {
				note(err)
				continue
			}
			return c.Seed, nil
		}
		note(errors.New("no provenance referrer matches the one the signature names"))
	}
	return "", first
}

// verifiedSeed is the one reading of an artifact's seed that a gate may use.
func verifiedSeed(dist, project, tag, osn, arch, want string) (string, error) {
	ledger, _, err := verifiedSeedArtifact(dist, project, tag, osn, arch, want)
	return ledger, err
}

// verifiedSeedArtifact is verifiedSeed that also returns the artifact digest the
// signature vouches for, so a caller can compare BYTES against it.
func verifiedSeedArtifact(dist, project, tag, osn, arch, want string) (ledger, digest string, err error) {
	digest, payloads, refs, err := sourceVerified(dist, project, tag, osn, arch)
	if err != nil {
		return "", "", fmt.Errorf("cannot read or authenticate the source provenance from %s: %w", dist, err)
	}
	ledger, err = authenticatedSeed(digest, payloads, refs, want)
	if err != nil {
		return "", "", err
	}
	return ledger, digest, nil
}
