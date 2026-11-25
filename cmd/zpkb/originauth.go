package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/artifact"
)

// What a promotion believes about an artifact has to come from something the
// registry cannot rewrite. The provenance referrer is stored beside the artifact
// and carries no signature of its own, so a fact read from it alone is whatever
// the registry says it is.
//
// The signature, on the other hand, is checked against a trusted key. Its payload
// has an `optional` object that the signature covers, so the facts a gate needs
// are written THERE: the sha256 of the provenance document, and the sovereign
// fact. A gate reads them only out of a payload that artifact's VerifiedPayloads
// returned, i.e. one made by a trusted key over exactly this artifact digest
// and naming this project and version.

const (
	// optProvenance is the sha256 (hex) of the in-toto provenance referrer.
	optProvenance = "zpkb-provenance-sha256"
	// optSovereign is "1" when the build ran inside the sovereign rootfs.
	optSovereign = "zpkb-sovereign"
	// optSeed is the sha256 (hex) of the seed ledger: the artifacts of ANOTHER
	// registry that served as the build environment of this build. It is signed,
	// so the fact cannot be dropped from an artifact after the build.
	optSeed = "zpkb-seed"

	// maxClaimBytes bounds a payload before it is parsed: the signed payload is
	// a few hundred bytes, and what a registry serves is not trusted to say so.
	maxClaimBytes = 16 << 10
)

// originClaims are the facts a signed payload carries.
type originClaims struct {
	ManifestDigest string
	Provenance     string
	Sovereign      string
	Seed           string
}

// originSigning builds the simple-signing payload that goes under the signature,
// with the origin facts in its `optional` object. It replaces sign's
// SimpleSigningPayload for publishing, which fixes `optional` to null.
var originSigning = func(dockerRef, manifestDigest string, c originClaims) ([]byte, error) {
	opt := map[string]string{}
	if c.Provenance != "" {
		opt[optProvenance] = c.Provenance
	}
	if c.Sovereign != "" {
		opt[optSovereign] = c.Sovereign
	}
	if c.Seed != "" {
		opt[optSeed] = c.Seed
	}
	type identity struct {
		DockerReference string `json:"docker-reference"`
	}
	type image struct {
		DockerManifestDigest string `json:"docker-manifest-digest"`
	}
	type critical struct {
		Identity identity `json:"identity"`
		Image    image    `json:"image"`
		Type     string   `json:"type"`
	}
	p := struct {
		Critical critical          `json:"critical"`
		Optional map[string]string `json:"optional"`
	}{
		Critical: critical{
			Identity: identity{DockerReference: dockerRef},
			Image:    image{DockerManifestDigest: manifestDigest},
			Type:     "cosign container image signature",
		},
	}
	if len(opt) > 0 {
		p.Optional = opt
	}
	return json.Marshal(p)
}

// parseOriginClaims reads the origin facts out of a signed payload. A payload
// that is oversized, is not JSON, or has a non-string value among the facts is an
// error, never a partial answer.
func parseOriginClaims(payload []byte) (originClaims, error) {
	if len(payload) > maxClaimBytes {
		return originClaims{}, errors.New("signed payload is oversized")
	}
	var p struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
		Optional map[string]json.RawMessage `json:"optional"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return originClaims{}, fmt.Errorf("signed payload: %w", err)
	}
	c := originClaims{ManifestDigest: p.Critical.Image.Digest}
	for k, dst := range map[string]*string{optProvenance: &c.Provenance, optSovereign: &c.Sovereign, optSeed: &c.Seed} {
		raw, ok := p.Optional[k]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return originClaims{}, fmt.Errorf("signed payload: %s is not a string", k)
		}
	}
	return c, nil
}

// provenanceStatement is the part of the in-toto statement an origin check reads.
type provenanceStatement struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			ExternalParameters map[string]string `json:"externalParameters"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

// authenticatedOrigin returns the origin of the artifact with the given digest,
// or an error saying what is missing. digest is the artifact's layer digest as
// the registry's manifest names it; payloads are the signed payloads
// VerifiedPayloads returned for it; refs are the referrers the registry serves.
//
// A provenance counts only if its sha256 is the one a verified payload names, its
// subject is this digest, and the verified payload says sovereign. Every
// other combination is a refusal, and the reason names which.
func authenticatedOrigin(digest string, payloads [][]byte, refs []artifact.Referrer) (provOrigin, error) {
	if len(payloads) == 0 {
		return provOrigin{}, errors.New("no signature vouches for this artifact")
	}
	want := strings.TrimPrefix(digest, "sha256:")
	if want == "" {
		return provOrigin{}, errors.New("the artifact digest is unknown")
	}
	var prov [][]byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			prov = append(prov, r.Blob)
		}
	}
	if len(prov) == 0 {
		return provOrigin{}, errNoProvenance
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
		if c.ManifestDigest != digest {
			note(errors.New("a signed claim is about another artifact digest"))
			continue
		}
		if c.Provenance == "" {
			note(errors.New("the signature carries no claim about the provenance (published before zpkb signed one)"))
			continue
		}
		for _, raw := range prov {
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != c.Provenance {
				continue
			}
			o, err := checkProvenance(raw, want, c)
			if err != nil {
				note(err)
				continue
			}
			return o, nil
		}
		note(errors.New("no provenance referrer matches the one the signature names"))
	}
	return provOrigin{}, first
}

// checkProvenance applies the rules to a provenance whose sha256 the signature
// names.
func checkProvenance(raw []byte, wantSubject string, c originClaims) (provOrigin, error) {
	var st provenanceStatement
	if err := json.Unmarshal(raw, &st); err != nil {
		return provOrigin{}, fmt.Errorf("provenance: %w", err)
	}
	subject := false
	for _, s := range st.Subject {
		if s.Digest["sha256"] == wantSubject {
			subject = true
		}
	}
	if !subject {
		return provOrigin{}, errors.New("the provenance is about another artifact digest")
	}
	if c.Seed != "" {
		return provOrigin{}, fmt.Errorf("the build used a seed (ledger sha256:%s) as its build environment: a seed-built artifact is never promoted — only a rebuild from our own outputs is", c.Seed)
	}
	if c.Sovereign != "1" {
		return provOrigin{}, fmt.Errorf("the signed claim says sovereign=%q: the build did not state that it ran inside the sovereign rootfs", c.Sovereign)
	}
	p := st.Predicate.BuildDefinition.ExternalParameters
	if p["bootstrap"] != "0" {
		return provOrigin{}, fmt.Errorf("the provenance records bootstrap=%q", p["bootstrap"])
	}
	return provOrigin{Bootstrap: "0", Sovereign: "1", Dist: p["inputs-from"], Digest: "sha256:" + wantSubject}, nil
}

// sourceVerified is the seam that reads what a promotion needs from a registry:
// the artifact digest, the signed payloads that vouch for it (an error unless
// the trust threshold is met), and the referrers.
var sourceVerified = func(dist, project, tag, osn, arch string) (string, [][]byte, []artifact.Referrer, error) {
	c, err := artifact.NewOCIClient(dist)
	if err != nil {
		return "", nil, nil, err
	}
	var (
		digest   string
		payloads [][]byte
		refs     []artifact.Referrer
	)
	err = underSourceTrust(sourceTrust, func() (e error) {
		digest, payloads, refs, e = readVerifiedVia(c, project, tag, osn, arch)
		return e
	})
	return digest, payloads, refs, err
}

// sourceTag is the seam that names the tag a promotion's source holds a version
// under, for the DOWNLOAD that follows the authenticated read.
//
// ⛔ THE READ AND THE DOWNLOAD MUST ASK FOR THE SAME TAG. The origin read goes
// through resolveBuildTag (`1.11.1` -> `1.11.1-h<hash>`), and the download used to
// pass the bare version to the registry, which answers "not found" about an
// artifact it holds: a promotion from a seed written by publish-stage verified
// the origin and then failed to fetch (go-zpkg/packages promo-r3, lz4.org 1.11.1).
var sourceTag = func(dist, project, ver, osn, arch string) (string, error) {
	c, err := artifact.NewOCIClient(dist)
	if err != nil {
		return "", err
	}
	return resolveBuildTag(c, project, ver, osn, arch)
}

// tagSource is what resolving a version to a registry tag asks of a registry.
type tagSource interface {
	ListTags(project string) ([]string, error)
	HasPlatform(project, ver, osn, arch string) (bool, error)
}

// resolveBuildTag turns a version into the tag a registry holds it under.
//
// ⛔ A VERSION IS NOT A TAG. `zpkb publish-stage` lands a build under
// `<version>-h<hash>` (buildTag); the bare version was the address before a build
// had an identity, and asking for it answers "not found" about a registry that
// holds the artifact. The rule is the installer's (artifact's PickVersionFor):
//
//   - a tag that already carries a build hash is used as given;
//   - the builds of the version that carry THIS platform are listed: exactly one
//     is used; several are REFUSED, naming each, because "the newest" of two
//     builds is whichever the registry listed last and a promotion would sign a
//     different artifact tomorrow;
//   - with no hashed build, the bare tag is tried (artifacts published before
//     builds had identities), and only then is the version declared absent.
func resolveBuildTag(c tagSource, project, tag, osn, arch string) (string, error) {
	if _, h := artifact.SplitVariantHash(tag); h != "" {
		return tag, nil
	}
	all, err := c.ListTags(project)
	if err != nil {
		return "", err
	}
	var builds []string
	for _, t := range all {
		if v, h := artifact.SplitVariantHash(t); h == "" || v != tag {
			continue
		}
		ok, err := c.HasPlatform(project, t, osn, arch)
		if err != nil {
			return "", err
		}
		if ok {
			builds = append(builds, t)
		}
	}
	switch len(builds) {
	case 1:
		return builds[0], nil
	case 0:
		return tag, nil // the bare tag; its absence is reported by the read that follows
	}
	sort.Strings(builds)
	return "", fmt.Errorf("%s %s has %d builds for %s/%s (%s): refusing to pick one — name the build's tag",
		project, tag, len(builds), osn, arch, strings.Join(builds, ", "))
}

// sourceClient is an OCI registry as the promotion reads it.
type sourceClient interface {
	originReader
	tagSource
}

// readVerifiedVia resolves the version to the tag the registry holds, then reads.
func readVerifiedVia(c sourceClient, project, ver, osn, arch string) (string, [][]byte, []artifact.Referrer, error) {
	tag, err := resolveBuildTag(c, project, ver, osn, arch)
	if err != nil {
		return "", nil, nil, err
	}
	return readVerified(c, project, tag, osn, arch)
}

// originReader is what readVerified asks of a registry client.
type originReader interface {
	ArtifactDigest(project, ver, osn, arch string) (string, error)
	VerifiedPayloads(project, ver, osn, arch, digest string) ([][]byte, error)
	FetchAttestations(project, ver, osn, arch string) ([]artifact.Referrer, map[string]string, error)
}

// readVerified is the three reads, in the order that matters: the digest, then
// the payloads verified for exactly that digest, then the referrers. Any failure
// is an error, never a partial answer.
func readVerified(c originReader, project, tag, osn, arch string) (string, [][]byte, []artifact.Referrer, error) {
	digest, err := c.ArtifactDigest(project, tag, osn, arch)
	if err != nil {
		return "", nil, nil, err
	}
	payloads, err := c.VerifiedPayloads(project, tag, osn, arch, digest)
	if err != nil {
		return "", nil, nil, err
	}
	refs, _, err := c.FetchAttestations(project, tag, osn, arch)
	if err != nil {
		return "", nil, nil, err
	}
	return digest, payloads, refs, nil
}

// verifiedOrigin is the one reading of an artifact's origin that a gate may use.
func verifiedOrigin(dist, project, tag, osn, arch string) (provOrigin, error) {
	digest, payloads, refs, err := sourceVerified(dist, project, tag, osn, arch)
	if err != nil {
		// Not "not promotable": that is a verdict about the artifact, and this
		// is a registry that would not answer or an artifact that is not signed
		// by a trusted key, which the caller has to be able to tell apart.
		return provOrigin{}, fmt.Errorf("cannot read or authenticate the source provenance from %s: %w", dist, err)
	}
	o, err := authenticatedOrigin(digest, payloads, refs)
	if err != nil {
		return provOrigin{}, fmt.Errorf("not promotable: %w", err)
	}
	return o, nil
}

// promotionPreconditions refuses a promotion whose source cannot be
// authenticated: a mirror that is not an OCI registry has no signatures at all,
// and a run with verification off would read them without checking.
func promotionPreconditions(mirror string) error {
	if !strings.HasPrefix(mirror, "oci://") {
		return fmt.Errorf("--require-origin needs an oci:// --mirror-from: %q carries no signatures to authenticate the provenance with", mirror)
	}
	if !artifact.VerifyRequired() {
		return errors.New("--require-origin needs signature verification on, and ZPKG_VERIFY turns it off")
	}
	return nil
}

// Sovereign is a fact about the machine the build ran on, measured by the build
// itself and not read from a flag a workflow could set anywhere. The sovereign
// rootfs is built from scratch: no system C headers, and every compiler name
// that exists in a system directory is a stub that `zpkb builder` wrote for an
// artifact. A runner with its own gcc or its own libc headers is not it.

// sovereignRoot is where the probe looks; a seam for tests.
var sovereignRoot = "/"

// hostToolNames are the names whose presence outside a stub means the host's
// toolchain is on the machine.
var hostToolNames = []string{"cc", "gcc", "g++", "c++", "clang", "clang++", "ld", "as", "tcc"}

// hostToolDirs are the system directories the probe reads.
var hostToolDirs = []string{"usr/bin", "bin", "usr/local/bin", "usr/sbin", "sbin"}

// stubPrefix begins every file artifact.StubBinsStaged writes.
const stubPrefix = "#!/bin/sh\nexport LD_LIBRARY_PATH="

// hostToolchainUnder names what is on this machine under root that a sovereign
// rootfs does not have, or "" when nothing is.
func hostToolchainUnder(root string) string {
	if _, err := os.Lstat(filepath.Join(root, "usr/include/stdio.h")); err == nil {
		return "/usr/include/stdio.h"
	}
	for _, d := range hostToolDirs {
		for _, n := range hostToolNames {
			p := filepath.Join(root, d, n)
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if !fi.Mode().IsRegular() || !isStub(p) {
				return "/" + filepath.ToSlash(filepath.Join(d, n))
			}
		}
	}
	return ""
}

// isStub reports whether the file is one of the shell stubs.
func isStub(p string) bool {
	buf := make([]byte, len(stubPrefix))
	n := 0
	f, err := os.Open(p)
	if err == nil {
		n, _ = f.Read(buf)
		f.Close()
	}
	return err == nil && bytes.Equal(buf[:n], []byte(stubPrefix))
}

// sovereignClaim returns the value the build records: "1" only when the
// sovereign libc was selected, the host toolchain was not asked for, and the
// machine has none. The second result is the reason for a "0".
func sovereignClaim(libc string, bootstrap bool, root string) (string, string) {
	switch {
	case libc != "zpkx":
		return "0", "--libc zpkx was not selected"
	case bootstrap:
		return "0", "--bootstrap takes tools from the host"
	}
	if host := hostToolchainUnder(root); host != "" {
		return "0", "the machine has " + host + ", which a sovereign rootfs does not"
	}
	return "1", ""
}
