package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
)

var testTarball = []byte("artifact")

// testDigest is the layer digest of testTarball, as a registry names it.
var testDigest = digestOf(testTarball)

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// signedFixture builds the referrers of testTarball through the PRODUCTION path
// with a real key, and returns the digest, the signed payloads and the
// referrers a registry would serve.
func signedFixture(t *testing.T, o provOrigin) (string, [][]byte, []artifact.Referrer) {
	t.Helper()
	return signedFixtureFor(t, testTarball, o)
}

func signedFixtureFor(t *testing.T, tarball []byte, o provOrigin) (string, [][]byte, []artifact.Referrer) {
	t.Helper()
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "s390x",
		tarball, build.SourceRef{}, nil, time.Unix(0, 0).UTC(), kp, o)
	if err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for _, r := range refs {
		if r.ArtifactType == artifact.ArtifactTypeSignature {
			payloads = append(payloads, r.Blob)
		}
	}
	return digestOf(tarball), payloads, refs
}

// stubVerified points the authenticated registry read at what a registry
// signed by a trusted key would serve for an artifact with this origin.
func stubVerified(t *testing.T, o provOrigin, err error) {
	t.Helper()
	d, p, r := signedFixture(t, o)
	old := sourceVerified
	t.Cleanup(func() { sourceVerified = old })
	sourceVerified = func(_, _, _, _, _ string) (string, [][]byte, []artifact.Referrer, error) {
		if err != nil {
			return "", nil, nil, err
		}
		return d, p, r, nil
	}
}

// TestGenuineOriginIsAuthenticated is the positive control for every refusal
// below: an artifact signed by the production path, sovereign, is accepted, and
// the facts come back from the signed claim.
func TestGenuineOriginIsAuthenticated(t *testing.T) {
	d, p, r := signedFixture(t, sovereignSource)
	o, err := authenticatedOrigin(d, p, r)
	if err != nil {
		t.Fatalf("a genuine sovereign artifact was refused: %v", err)
	}
	if o.Sovereign != "1" || o.Bootstrap != "0" || o.Dist != sovereignSource.Dist || o.Digest != d {
		t.Errorf("origin = %+v", o)
	}
}

// ⛔ TestAnUnsignedReferrerIsRefused: a provenance that no signature names is
// whatever the registry says it is, however well it reads.
func TestAnUnsignedReferrerIsRefused(t *testing.T) {
	d, _, r := signedFixture(t, sovereignSource)
	if _, err := authenticatedOrigin(d, nil, r); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Errorf("a provenance with no verified signature was accepted: %v", err)
	}
}

// ⛔ TestAForgedProvenanceIsRefused: the registry swaps the provenance for one
// that says what the gate wants, and leaves the real signature in place.
func TestAForgedProvenanceIsRefused(t *testing.T) {
	d, p, r := signedFixture(t, provOrigin{Bootstrap: "1", Sovereign: "0"})
	forged := forgedProvenance(t, d, "0", "1")
	var refs []artifact.Referrer
	for _, x := range r {
		if x.ArtifactType == artifactInToto {
			x.Blob = forged
		}
		refs = append(refs, x)
	}
	if _, err := authenticatedOrigin(d, p, refs); err == nil || !strings.Contains(err.Error(), "no provenance referrer matches") {
		t.Errorf("a forged provenance was accepted: %v", err)
	}
}

// ⛔ TestAReferrerFromAnotherDigestIsRefused: a genuine, signed, sovereign
// provenance of ANOTHER artifact is planted beside this one.
func TestAReferrerFromAnotherDigestIsRefused(t *testing.T) {
	// The attacker's own tarball, genuinely sovereign.
	_, otherPayloads, otherRefs := signedFixtureFor(t, []byte("another artifact"), sovereignSource)
	// The artifact being promoted: not sovereign.
	d, p, _ := signedFixture(t, provOrigin{Bootstrap: "0", Sovereign: "0"})

	t.Run("their provenance beside our signature", func(t *testing.T) {
		if _, err := authenticatedOrigin(d, p, otherRefs); err == nil {
			t.Error("a provenance of another artifact was accepted")
		}
	})
	t.Run("their signature for our digest", func(t *testing.T) {
		if _, err := authenticatedOrigin(d, otherPayloads, otherRefs); err == nil ||
			!strings.Contains(err.Error(), "another artifact digest") {
			t.Errorf("a signed claim about another digest was accepted: %v", err)
		}
	})
	t.Run("a matching hash but a provenance whose subject is another digest", func(t *testing.T) {
		// A signed claim that names a document whose subject is not this artifact.
		other := forgedProvenance(t, digestOf([]byte("elsewhere")), "0", "1")
		sum := sha256.Sum256(other)
		pl, err := originSigning("pkg:generic/acme.org/tool@1.2.3", d,
			originClaims{Provenance: hex.EncodeToString(sum[:]), Sovereign: "1"})
		if err != nil {
			t.Fatal(err)
		}
		refs := []artifact.Referrer{{ArtifactType: artifactInToto, Blob: other}}
		if _, err := authenticatedOrigin(d, [][]byte{pl}, refs); err == nil ||
			!strings.Contains(err.Error(), "another artifact digest") {
			t.Errorf("a provenance about another digest was accepted: %v", err)
		}
	})
}

// ⛔ TestANonSovereignClaimIsRefused: signed, matching and bootstrap=0, but the
// build did not claim to be sovereign, or claimed it as something else.
func TestANonSovereignClaimIsRefused(t *testing.T) {
	for _, sov := range []string{"", "0", "true", "yes", " 1"} {
		d, p, r := signedFixture(t, provOrigin{Bootstrap: "0", Sovereign: sov})
		if _, err := authenticatedOrigin(d, p, r); err == nil || !strings.Contains(err.Error(), "sovereign") {
			t.Errorf("sovereign=%q was accepted: %v", sov, err)
		}
	}
}

// TestAMissingOrOversizedClaimIsRefused covers the signature of an artifact
// signed before zpkb wrote a provenance claim, and unreadable payloads.
func TestAMissingOrOversizedClaimIsRefused(t *testing.T) {
	d, _, r := signedFixture(t, sovereignSource)
	old, err := simpleSigning("pkg:generic/acme.org/tool@1.2.3", d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticatedOrigin(d, [][]byte{old}, r); err == nil || !strings.Contains(err.Error(), "no claim about the provenance") {
		t.Errorf("a signature with no claim was accepted: %v", err)
	}
	for name, pl := range map[string][]byte{
		"not json":  []byte("{"),
		"oversized": bytes.Repeat([]byte(" "), maxClaimBytes+1),
		"non-string": []byte(`{"critical":{"image":{"docker-manifest-digest":"` + d +
			`"}},"optional":{"zpkb-sovereign":1}}`),
	} {
		if _, err := authenticatedOrigin(d, [][]byte{pl}, r); err == nil {
			t.Errorf("%s payload was accepted", name)
		}
	}
	if _, err := authenticatedOrigin(d, [][]byte{old}, nil); err == nil {
		t.Error("an artifact with no provenance referrer at all was accepted")
	}
}

// TestAnotherInTotoReferrerCannotShadowTheSignedOne: the registry adds a second
// provenance; only the one the signature names is read.
func TestAnotherInTotoReferrerCannotShadowTheSignedOne(t *testing.T) {
	d, p, r := signedFixture(t, sovereignSource)
	evil := forgedProvenance(t, d, "1", "0")
	refs := append([]artifact.Referrer{{ArtifactType: artifactInToto, Blob: evil}}, r...)
	if _, err := authenticatedOrigin(d, p, refs); err != nil {
		t.Errorf("an extra referrer ahead of the signed one broke the genuine path: %v", err)
	}
}

func forgedProvenance(t *testing.T, digest, bootstrap, sov string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"subject": []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
		"predicate": map[string]any{"buildDefinition": map[string]any{
			"externalParameters": map[string]string{"bootstrap": bootstrap, "sovereign": sov},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBuildReferrersSignsTheProvenanceAndTheSovereignFact: the publishing path
// puts the facts under the signature, and the unsigned provenance says the same.
func TestBuildReferrersSignsTheProvenanceAndTheSovereignFact(t *testing.T) {
	_, p, r := signedFixture(t, sovereignSource)
	if len(p) != 1 {
		t.Fatalf("%d signature payloads", len(p))
	}
	c, err := parseOriginClaims(p[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.Sovereign != "1" || c.ManifestDigest != testDigest {
		t.Errorf("claims = %+v", c)
	}
	for _, x := range r {
		if x.ArtifactType == artifactInToto {
			sum := sha256.Sum256(x.Blob)
			if hex.EncodeToString(sum[:]) != c.Provenance {
				t.Error("the signed claim does not name the provenance that is published")
			}
			if !strings.Contains(string(x.Blob), `"sovereign": "1"`) {
				t.Errorf("the provenance does not record the sovereign fact: %s", x.Blob)
			}
		}
	}
}

// FuzzParseOriginClaims: whatever a registry serves as a signed payload, the
// parser returns a value or an error and never panics.
func FuzzParseOriginClaims(f *testing.F) {
	good, _ := originSigning("pkg:generic/a@1", "sha256:00", originClaims{Provenance: "ab", Sovereign: "1"})
	f.Add(good)
	f.Add([]byte(`{"optional":{"zpkb-sovereign":null}}`))
	f.Add([]byte(`{"optional":{"zpkb-provenance-sha256":[1]}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := parseOriginClaims(b)
		if err != nil && c != (originClaims{}) {
			t.Fatalf("an error came with a partial answer: %+v", c)
		}
	})
}

// writeFile makes a file and its parents under root.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// ⛔ TestSovereignIsMeasuredNotClaimed: the same libc flag on a machine with a
// compiler or with system headers does not produce the claim.
func TestSovereignIsMeasuredNotClaimed(t *testing.T) {
	stub := stubPrefix + "\"/x\"\nexec /x \"$@\"\n"
	t.Run("scratch rootfs with stubs", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "usr/bin/cc", stub)
		writeFile(t, root, "usr/bin/ld", stub)
		if got, why := sovereignClaim("zpkx", false, root); got != "1" {
			t.Errorf("a sovereign rootfs was refused: %s", why)
		}
	})
	t.Run("an ELF compiler", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "usr/bin/gcc", "\x7fELF")
		if got, why := sovereignClaim("zpkx", false, root); got != "0" || !strings.Contains(why, "/usr/bin/gcc") {
			t.Errorf("got %q (%s)", got, why)
		}
	})
	t.Run("a symlinked compiler", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "etc/alternatives/cc", stub)
		if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/alternatives/cc", filepath.Join(root, "usr/bin/cc")); err != nil {
			t.Fatal(err)
		}
		if got, _ := sovereignClaim("zpkx", false, root); got != "0" {
			t.Error("a symlinked cc passed as a stub")
		}
	})
	t.Run("system headers", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "usr/include/stdio.h", "")
		if got, _ := sovereignClaim("zpkx", false, root); got != "0" {
			t.Error("a machine with libc headers claimed to be sovereign")
		}
	})
	t.Run("flags", func(t *testing.T) {
		root := t.TempDir()
		if got, _ := sovereignClaim("", false, root); got != "0" {
			t.Error("a build without --libc zpkx claimed to be sovereign")
		}
		if got, _ := sovereignClaim("zpkx", true, root); got != "0" {
			t.Error("a --bootstrap build claimed to be sovereign")
		}
	})
}

// TestTheFactoryRecordsTheMeasuredSovereignFact: from the flag to what is
// published, on a machine that is not sovereign and on one that is.
func TestTheFactoryRecordsTheMeasuredSovereignFact(t *testing.T) {
	old := sovereignRoot
	t.Cleanup(func() { sovereignRoot = old })
	for _, c := range []struct {
		name, want string
		setup      func(root string)
	}{
		{"host with a compiler", "0", func(root string) { writeFile(t, root, "usr/bin/gcc", "\x7fELF") }},
		{"scratch", "1", func(string) {}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sovereignRoot = t.TempDir()
			c.setup(sovereignRoot)
			h := newFactoryHarness(t)
			writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
			if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1", "--libc", "zpkx"); code != 0 {
				t.Fatalf("code = %d: %s", code, h.errb.String())
			}
			if len(h.published) == 0 || h.published[0].origin.Sovereign != c.want {
				t.Errorf("published = %+v, want sovereign %q", h.published, c.want)
			}
		})
	}
}

// ⛔ TestAnOCIMirrorKeepsVerification: --mirror-from an oci:// registry does not
// switch signature verification off; a static dist, which has none, still does.
func TestAnOCIMirrorKeepsVerification(t *testing.T) {
	old := artifact.DistBase
	t.Cleanup(func() { artifact.DistBase = old })
	t.Run("oci", func(t *testing.T) {
		t.Setenv("ZPKG_VERIFY", "")
		os.Unsetenv("ZPKG_VERIFY")
		if err := setUpstreamDist("oci://registry.example/seed", false); err != nil {
			t.Fatal(err)
		}
		if _, set := os.LookupEnv("ZPKG_VERIFY"); set || !artifact.VerifyRequired() {
			t.Error("an oci:// mirror turned verification off")
		}
	})
	t.Run("static dist", func(t *testing.T) {
		t.Setenv("ZPKG_VERIFY", "")
		os.Unsetenv("ZPKG_VERIFY")
		t.Cleanup(func() { os.Unsetenv("ZPKG_VERIFY") })
		if err := setUpstreamDist("https://dist.example", false); err != nil {
			t.Fatal(err)
		}
		if artifact.VerifyRequired() {
			t.Error("a static dist cannot be verified and was not copied unverified")
		}
	})
	t.Run("promotion refuses a static dist", func(t *testing.T) {
		if err := setUpstreamDist("https://dist.example", true); err == nil {
			t.Error("--require-origin accepted a static dist")
		}
	})
}

// TestTheParserRefusesOnItsOwn pins the parser's own refusals, so none of them
// is held only by a check further down.
func TestTheParserRefusesOnItsOwn(t *testing.T) {
	pad := `{"critical":{"image":{"docker-manifest-digest":"sha256:00"}},"optional":{"zpkb-sovereign":"1"},"x":"` +
		strings.Repeat("a", maxClaimBytes) + `"}`
	for name, pl := range map[string]string{
		"oversized but valid json": pad,
		"not json":                 "{",
		"non-string sovereign":     `{"optional":{"zpkb-sovereign":1}}`,
		"non-string provenance":    `{"optional":{"zpkb-provenance-sha256":["a"]}}`,
	} {
		if c, err := parseOriginClaims([]byte(pl)); err == nil || c != (originClaims{}) {
			t.Errorf("%s: c=%+v err=%v", name, c, err)
		}
	}
}

// TestAnEmptyDigestAndNoReferrersAreRefusedByTheirOwnGuards.
func TestAnEmptyDigestAndNoReferrersAreRefusedByTheirOwnGuards(t *testing.T) {
	d, p, r := signedFixture(t, sovereignSource)
	if _, err := authenticatedOrigin("", p, r); err == nil || !strings.Contains(err.Error(), "digest is unknown") {
		t.Errorf("empty digest: %v", err)
	}
	if _, err := authenticatedOrigin(d, p, nil); err != errNoProvenance {
		t.Errorf("no referrers: %v", err)
	}
}

// TestAProvenanceThatIsNotJSONIsRefused: its hash is the one the signature names,
// so only the parse can refuse it.
func TestAProvenanceThatIsNotJSONIsRefused(t *testing.T) {
	d, _, _ := signedFixture(t, sovereignSource)
	raw := []byte("not json")
	sum := sha256.Sum256(raw)
	pl, err := originSigning("pkg:generic/acme.org/tool@1.2.3", d,
		originClaims{Provenance: hex.EncodeToString(sum[:]), Sovereign: "1"})
	if err != nil {
		t.Fatal(err)
	}
	refs := []artifact.Referrer{{ArtifactType: artifactInToto, Blob: raw}}
	if _, err := authenticatedOrigin(d, [][]byte{pl}, refs); err == nil || !strings.Contains(err.Error(), "provenance:") {
		t.Errorf("err = %v", err)
	}
}
