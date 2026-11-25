package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

var testSeedEntries = []artifact.SeedEntry{
	{Project: "gnu.org/make", Version: "4.4.1", Digest: "sha256:" + strings.Repeat("a", 64), Signers: []string{"go-pkgx"}, Source: "oci://ghcr.io/go-pkgx/packages"},
	{Project: "llvm.org", Version: "23.1.2", Digest: "sha256:" + strings.Repeat("b", 64), Signers: []string{"go-pkgx"}, Source: "oci://ghcr.io/go-pkgx/packages"},
}

func seededOrigin() provOrigin {
	return provOrigin{
		Bootstrap: "0", Sovereign: "1", Dist: "http://10.46.81.1:5111",
		Seed: artifact.SeedLedgerDigest(testSeedEntries), SeedEntries: testSeedEntries,
	}
}

func writeLedger(t *testing.T, es []artifact.SeedEntry) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range es {
		line, _ := json.Marshal(e)
		b.Write(line)
		b.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "seed.jsonl")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A seed-built artifact names its seed in the SIGNED claim and in the
// provenance, and is never promotable.
func TestASeedBuiltArtifactNamesItsSeedAndIsNotPromotable(t *testing.T) {
	o := seededOrigin()
	d, p, r := signedFixture(t, o)

	var prov []byte
	for _, x := range r {
		if x.ArtifactType == artifactInToto {
			prov = x.Blob
		}
	}
	var st provenanceStatement
	if err := json.Unmarshal(prov, &st); err != nil {
		t.Fatal(err)
	}
	if got := st.Predicate.BuildDefinition.ExternalParameters; got["seed"] != o.Seed || got["seed-source"] != "oci://ghcr.io/go-pkgx/packages" {
		t.Errorf("externalParameters = %v", got)
	}
	for _, want := range []string{
		strings.Repeat("a", 64), strings.Repeat("b", 64),
		"gnu.org/make", "llvm.org",
	} {
		if !strings.Contains(string(prov), want) {
			t.Errorf("provenance does not carry %s: %s", want, prov)
		}
	}
	c, err := parseOriginClaims(p[0])
	if err != nil || c.Seed != o.Seed {
		t.Fatalf("signed claim seed = %q, %v; want %q", c.Seed, err, o.Seed)
	}
	// sovereign=1 and bootstrap=0 would pass every other rule: the seed alone refuses.
	if _, err := authenticatedOrigin(d, p, r); err == nil || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("a seed-built artifact was promotable: %v", err)
	}
}

func TestAnArtifactBuiltWithoutASeedStaysPromotableAndSaysNothingOfOne(t *testing.T) {
	d, p, r := signedFixture(t, sovereignSource)
	if _, err := authenticatedOrigin(d, p, r); err != nil {
		t.Fatalf("a sovereign unseeded artifact was refused: %v", err)
	}
	for _, x := range r {
		if x.ArtifactType == artifactInToto && strings.Contains(string(x.Blob), `"seed`) {
			t.Errorf("an unseeded provenance mentions a seed: %s", x.Blob)
		}
	}
	c, _ := parseOriginClaims(p[0])
	if c.Seed != "" {
		t.Errorf("an unseeded claim carries seed %q", c.Seed)
	}
}

// The seed claim is a string like the others.
func TestASeedClaimThatIsNotAStringIsRefused(t *testing.T) {
	pl := []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:x"}},"optional":{"zpkb-seed":7}}`)
	if _, err := parseOriginClaims(pl); err == nil {
		t.Error("a numeric seed claim was accepted")
	}
}

func TestSeedFlagConsistency(t *testing.T) {
	cases := []struct {
		name               string
		ledger, from       string
		stageOnly          bool
		mirror             string
		wantErr, wantInMsg string
	}{
		{"neither", "", "", false, "", "", ""},
		{"both and staged", "l", "oci://x", true, "", "", ""},
		{"ledger without a seed in force", "l", "", true, "", "yes", "no seed is in force"},
		{"seed in force without a ledger", "", "oci://x", true, "", "yes", "without naming their seed"},
		{"not staged", "l", "oci://x", false, "", "yes", "--stage-only"},
		{"with a mirror", "l", "oci://x", true, "oci://y", "yes", "does not copy"},
	}
	for _, c := range cases {
		err := checkSeedFlags(c.ledger, c.from, c.stageOnly, c.mirror)
		if (err != nil) != (c.wantErr != "") {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.wantInMsg) {
			t.Errorf("%s: %v does not say %q", c.name, err, c.wantInMsg)
		}
	}
}

func TestASeedLedgerIsCarriedIntoThePlanAndCanOnlyGrow(t *testing.T) {
	p := &stagePlan{}
	if err := applySeed(p, writeLedger(t, testSeedEntries[:1])); err != nil {
		t.Fatal(err)
	}
	if p.Seed == nil || p.Seed.Digest != artifact.SeedLedgerDigest(p.Seed.Entries) || len(p.Seed.Entries) != 1 {
		t.Fatalf("seed = %+v", p.Seed)
	}
	// A later chunk shares the ledger, which has grown.
	if err := applySeed(p, writeLedger(t, testSeedEntries)); err != nil || len(p.Seed.Entries) != 2 {
		t.Fatalf("a grown ledger: %v, %+v", err, p.Seed)
	}
	// A ledger that lost an entry understates the seed.
	if err := applySeed(p, writeLedger(t, testSeedEntries[:1])); err == nil || !strings.Contains(err.Error(), "no longer has") {
		t.Fatalf("a shrunk ledger was accepted: %v", err)
	}
}

func TestAnEmptyOrMissingSeedLedgerIsRefused(t *testing.T) {
	if err := applySeed(&stagePlan{}, writeLedger(t, nil)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty ledger: %v", err)
	}
	if err := applySeed(&stagePlan{}, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing ledger was accepted")
	}
	// A ledger that cannot be read is refused for what it is, not reported as an
	// empty one (which would also be what a swallowed read error looked like).
	bad := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applySeed(&stagePlan{}, bad); err == nil || strings.Contains(err.Error(), "is empty") {
		t.Errorf("a corrupt ledger: %v", err)
	}
}

func TestOnePassHasOneSeed(t *testing.T) {
	seeded := &stagePlan{Seed: &stageSeed{Digest: "d", Entries: testSeedEntries}}
	unseeded := &stagePlan{Artifacts: []stageEntry{{Project: "p"}}}
	if err := checkPlanSeed(seeded, true); err != nil {
		t.Errorf("seeded on seeded: %v", err)
	}
	if err := checkPlanSeed(&stagePlan{}, true); err != nil {
		t.Errorf("seeded on empty: %v", err)
	}
	if err := checkPlanSeed(&stagePlan{}, false); err != nil {
		t.Errorf("unseeded on empty: %v", err)
	}
	if err := checkPlanSeed(unseeded, true); err == nil {
		t.Error("a seeded run extended unseeded artifacts")
	}
	if err := checkPlanSeed(seeded, false); err == nil {
		t.Error("an unseeded run extended a seeded plan")
	}
}

func planWith(t *testing.T, mutate func(p *stagePlan)) []byte {
	t.Helper()
	p := stagePlan{Schema: stagePlanSchema, Dist: "oci://x", Platform: "linux/x86-64", Builder: "b",
		Seed: &stageSeed{Digest: artifact.SeedLedgerDigest(testSeedEntries), Entries: append([]artifact.SeedEntry(nil), testSeedEntries...)}}
	mutate(&p)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAPlanSeedIsValidatedOnRead(t *testing.T) {
	if _, err := parseStagePlan(planWith(t, func(*stagePlan) {})); err != nil {
		t.Fatalf("a good seeded plan: %v", err)
	}
	bad := []struct {
		name   string
		mutate func(*stagePlan)
		want   string
	}{
		{"digest is not the ledger's", func(p *stagePlan) { p.Seed.Digest = strings.Repeat("0", 64) }, "not the ledger's"},
		{"no entries", func(p *stagePlan) { p.Seed.Entries = nil }, "names no artifact"},
		{"an entry with no digest", func(p *stagePlan) { p.Seed.Entries[0].Digest = "" }, "names no project"},
		{"a control character", func(p *stagePlan) { p.Seed.Entries[0].Source = "oci://a\nb" }, "control character"},
		{"a mirrored copy", func(p *stagePlan) {
			p.Artifacts = []stageEntry{{Project: "p", Mirror: &stageMirror{}}}
		}, "mirrored copy"},
	}
	for _, c := range bad {
		if _, err := parseStagePlan(planWith(t, c.mutate)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
}

func TestTheSeedDigestIsTheLedgersOnWriteAndRead(t *testing.T) {
	// A tampered entry with the old digest is caught.
	b := planWith(t, func(p *stagePlan) {
		p.Seed.Entries[0].Version = "9.9.9"
		p.Seed.Digest = artifact.SeedLedgerDigest(testSeedEntries)
	})
	if _, err := parseStagePlan(b); err == nil {
		t.Error("a plan whose seed entries do not hash to its digest was read")
	}
}

func TestBuilderSeedFlagsAreConsistent(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runBuilder([]string{"--seed-ledger", "l", "--dry-run"}, &out, &errb); rc != 2 || !strings.Contains(errb.String(), "--seed-from") {
		t.Errorf("ledger without a seed: rc=%d %q", rc, errb.String())
	}
	errb.Reset()
	if rc := runBuilder([]string{"--seed-from", "oci://ghcr.io/go-pkgx/packages", "--dist", "oci://ghcr.io/go-zpkg/packages", "--dry-run"}, &out, &errb); rc != 2 || !strings.Contains(errb.String(), "give one") {
		t.Errorf("--dist with a seed: rc=%d %q", rc, errb.String())
	}
	errb.Reset()
	if rc := runBuilder([]string{"--seed-from", "http://dist.pkgx.dev", "--dry-run"}, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "seed") {
		t.Errorf("an unsigned seed was accepted: rc=%d %q", rc, errb.String())
	}
}

// Both halves of the narrow rule: a seed is accepted as a build environment
// (zpkx proves that), and go-pkgx stays refused as a dependency source.
func TestGoPkgxStaysRefusedAsADependencySource(t *testing.T) {
	if err := artifact.CheckDistSource("oci://ghcr.io/go-pkgx/packages"); err == nil {
		t.Fatal("go-pkgx accepted as a dependency source")
	}
}

// A plan's seed is bounded: exactly the limit is read, one more is refused.
func TestAPlanSeedIsBounded(t *testing.T) {
	fill := func(n int) func(*stagePlan) {
		return func(p *stagePlan) {
			es := make([]artifact.SeedEntry, n)
			for i := range es {
				es[i] = testSeedEntries[0]
			}
			p.Seed.Entries = es
			p.Seed.Digest = artifact.SeedLedgerDigest(es)
		}
	}
	if _, err := parseStagePlan(planWith(t, fill(maxSeedEntries))); err != nil {
		t.Errorf("a seed of exactly %d entries: %v", maxSeedEntries, err)
	}
	if _, err := parseStagePlan(planWith(t, fill(maxSeedEntries+1))); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a seed of %d entries: %v", maxSeedEntries+1, err)
	}
}

// The factory itself, not only the helpers it calls, refuses and carries a seed.
func TestTheFactoryRefusesSeedFlagsWithoutASeed(t *testing.T) {
	r := newStageRig(t)
	t.Setenv("ZPKX_SEED_FROM", "")
	code := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist, "--seed-ledger", writeLedger(t, testSeedEntries))
	if code != 2 || !strings.Contains(r.h.errb.String(), "no seed is in force") {
		t.Errorf("code=%d err=%q", code, r.h.errb.String())
	}
}

func TestTheFactoryRefusesToMixSeededAndUnseededArtifactsInOneStage(t *testing.T) {
	r := newStageRig(t)
	t.Setenv("ZPKX_SEED_FROM", "")
	r.stage(t)
	t.Setenv("ZPKX_SEED_FROM", "oci://seed.test/x")
	code := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist, "--seed-ledger", writeLedger(t, testSeedEntries))
	if code != 1 || !strings.Contains(r.h.errb.String(), "one pass has one seed") {
		t.Errorf("code=%d err=%q", code, r.h.errb.String())
	}
}

func TestTheFactoryStagesTheSeedLedgerIntoThePlan(t *testing.T) {
	t.Setenv("ZPKX_SEED_FROM", "oci://seed.test/x")
	r := newStageRig(t)
	empty := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist, "--seed-ledger", writeLedger(t, nil))
	if empty != 1 || !strings.Contains(r.h.errb.String(), "is empty") {
		t.Fatalf("an empty ledger: code=%d err=%q", empty, r.h.errb.String())
	}
	if _, err := os.Stat(filepath.Join(r.h.artifacts, stagePlanName)); err == nil {
		t.Error("a plan was written under a seed that named nothing")
	}
	code := r.h.run(t, "--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist, "--seed-ledger", writeLedger(t, testSeedEntries))
	if code != 0 || !strings.Contains(r.h.out.String(), "seed: 2 artifact(s)") {
		t.Fatalf("code=%d out=%q err=%q", code, r.h.out.String(), r.h.errb.String())
	}
	b, err := os.ReadFile(filepath.Join(r.h.artifacts, stagePlanName))
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseStagePlan(b)
	if err != nil || p.Seed == nil || len(p.Seed.Entries) != 2 {
		t.Errorf("the plan does not carry the seed: %v %+v", err, p.Seed)
	}
}
