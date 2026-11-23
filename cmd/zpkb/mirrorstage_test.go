package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

const mirrorSeed = "oci://127.0.0.1:5000/seed"

// mirrorStageRig drives `factory --mirror-from --require-origin --stage-only`
// against a seed whose registry reads are stubbed, with the REAL publishArtifact
// behind publish-stage so what would be signed and pushed can be inspected.
type mirrorStageRig struct {
	*stageRig
	tarball []byte
}

// newMirrorStageRig stubs the seed: `served` is what its download answers and
// the signed facts are for `vouched` with origin `o`.
func newMirrorStageRig(t *testing.T) *mirrorStageRig {
	t.Helper()
	t.Setenv("ZPKG_VERIFY", "1")
	r := &mirrorStageRig{stageRig: newStageRig(t), tarball: stageTarball(t, "mirrored")}
	prevDown, prevVers, prevDist := factoryDownload, factoryUpstreamVersions, artifact.DistBase
	t.Cleanup(func() {
		factoryDownload, factoryUpstreamVersions, artifact.DistBase = prevDown, prevVers, prevDist
	})
	factoryUpstreamVersions = func(string, string, string) ([]artifact.Ver, error) {
		return []artifact.Ver{artifact.ParseVer("1.0")}, nil
	}
	return r
}

// serve makes the seed download answer with `served` and its signed read answer
// as a registry would for `vouched` carrying origin o (or err).
func (r *mirrorStageRig) serve(t *testing.T, served, vouched []byte, o provOrigin, err error) {
	t.Helper()
	factoryDownload = func(string, string, string, string) ([]byte, string, error) {
		return served, artifact.ExtTarGz, nil
	}
	d, p, refs := signedFixtureFor(t, vouched, o)
	old := sourceVerified
	t.Cleanup(func() { sourceVerified = old })
	sourceVerified = func(_, _, _, _, _ string) (string, [][]byte, []artifact.Referrer, error) {
		if err != nil {
			return "", nil, nil, err
		}
		return d, p, refs, nil
	}
}

func readPlan(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, stagePlanName))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func planEntries(m map[string]any) []any {
	a, _ := m["artifacts"].([]any)
	return a
}

// ⛔ The positive control for everything below, and the equality the feature is
// for: a verified seed artifact is staged with a `mirrored-verified` verdict
// (not `pass`), nothing is signed or pushed at stage time, and publish-stage
// signs and pushes it carrying the SOURCE's origin.
func TestStageOnlyMirrorStagesVerifiedAndPublishStageSignsIt(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin")
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
	}
	if len(r.pushes) != 0 || len(r.h.published) != 0 {
		t.Fatalf("a staging mirror pushed: %v %v", r.pushes, r.h.published)
	}
	es := planEntries(readPlan(t, r.h.artifacts))
	if len(es) != 1 {
		t.Fatalf("plan has %d entries, want 1", len(es))
	}
	e := es[0].(map[string]any)
	if e["test"] != "mirrored-verified" || e["test"] == "pass" {
		t.Errorf("verdict = %v, want mirrored-verified", e["test"])
	}
	m, _ := e["mirror"].(map[string]any)
	if m == nil || m["verified"] != true || m["from"] != mirrorSeed || m["digest"] != digestOf(r.tarball) {
		t.Errorf("mirror record = %v", e["mirror"])
	}
	// publish-stage signs it, and the republished provenance is the seed's.
	code, out, errb := r.publishStage("--to", stageDist, "--sign", r.key)
	if code != 0 || len(r.pushes) != 1 {
		t.Fatalf("publish-stage code=%d pushes=%d\n%s\n%s", code, len(r.pushes), out, errb)
	}
	if !strings.Contains(r.pushes[0], mirrorSeed) {
		t.Errorf("the republished provenance does not carry the seed's inputs registry")
	}
	if !strings.Contains(r.pushes[0], artifact.ArtifactTypeSignature) {
		t.Errorf("nothing signed")
	}
}

// ⛔ Each refusal at STAGE time, attributed by the failure record, with nothing
// staged and nothing publishable afterwards.
func TestStageOnlyMirrorRefusesWhatItCannotVerify(t *testing.T) {
	forged := stageTarball(t, "forged")
	other := stageTarball(t, "another artifact")
	for _, c := range []struct {
		name   string
		reason string
		setup  func(t *testing.T, r *mirrorStageRig)
	}{
		{"tampered tarball", "whose origin was authenticated", func(t *testing.T, r *mirrorStageRig) {
			r.serve(t, forged, r.tarball, sovereignSource, nil)
		}},
		{"missing origin claim", "sovereign", func(t *testing.T, r *mirrorStageRig) {
			r.serve(t, r.tarball, r.tarball, provOrigin{}, nil)
		}},
		{"host-built origin", "sovereign", func(t *testing.T, r *mirrorStageRig) {
			r.serve(t, r.tarball, r.tarball, provOrigin{Bootstrap: "1", Sovereign: "0", Dist: mirrorSeed}, nil)
		}},
		{"signature by a key we do not trust", "cannot read or authenticate", func(t *testing.T, r *mirrorStageRig) {
			r.serve(t, r.tarball, r.tarball, sovereignSource, os.ErrPermission)
		}},
		{"forged claim about another artifact", "another artifact digest", func(t *testing.T, r *mirrorStageRig) {
			r.serve(t, r.tarball, other, sovereignSource, nil)
			_, p, refs := signedFixtureFor(t, other, sovereignSource)
			sourceVerified = func(_, _, _, _, _ string) (string, [][]byte, []artifact.Referrer, error) {
				return digestOf(r.tarball), p, refs, nil
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newMirrorStageRig(t)
			c.setup(t, r)
			// The run's own status is not asserted: a factory records a failed
			// project and goes on, so the refusal is read from its failure record.
			r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
				"--mirror-from", mirrorSeed, "--require-origin")
			if d := r.h.detailFile(t); !strings.Contains(d, c.reason) {
				t.Errorf("failure record lacks %q:\n%s", c.reason, d)
			}
			if n := len(planEntries(readPlan(t, r.h.artifacts))); n != 0 {
				t.Errorf("%d entries staged despite the refusal", n)
			}
			if len(r.pushes) != 0 {
				t.Errorf("pushed: %v", r.pushes)
			}
		})
	}
}

// A version the plan cannot carry is a failure of the stage step, attributed
// as such, and stages nothing.
func TestStageOnlyMirrorFailsWhenTheEntryCannotBeRecorded(t *testing.T) {
	r := newMirrorStageRig(t)
	r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
	factoryUpstreamVersions = func(string, string, string) ([]artifact.Ver, error) {
		return []artifact.Ver{artifact.ParseVer("1.0 x")}, nil
	}
	r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
		"--mirror-from", mirrorSeed, "--require-origin")
	if d := r.h.detailFile(t); !strings.Contains(d, "stage") || !strings.Contains(d, "bad version") {
		t.Errorf("the failure record does not attribute it to the stage:\n%s", d)
	}
	if n := len(planEntries(readPlan(t, r.h.artifacts))); n != 0 {
		t.Errorf("%d entries staged", n)
	}
}

func TestStageOnlyMirrorNeedsRequireOriginAndVerification(t *testing.T) {
	t.Run("no --require-origin", func(t *testing.T) {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist, "--mirror-from", mirrorSeed)
		if code != 2 || !strings.Contains(r.h.errb.String(), "--require-origin") {
			t.Errorf("code=%d stderr=%q", code, r.h.errb.String())
		}
	})
	t.Run("verification off", func(t *testing.T) {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		t.Setenv("ZPKG_VERIFY", "0")
		code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
			"--mirror-from", mirrorSeed, "--require-origin")
		if code != 2 || !strings.Contains(r.h.errb.String(), "ZPKG_VERIFY") {
			t.Errorf("code=%d stderr=%q", code, r.h.errb.String())
		}
	})
	t.Run("signing key set", func(t *testing.T) {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		t.Setenv("SIGNING_KEY", "x")
		code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
			"--mirror-from", mirrorSeed, "--require-origin")
		if code != 2 {
			t.Errorf("code=%d", code)
		}
	})
}

// ⛔ publish-stage accepts `mirrored-verified` only with the record, so every
// way a plan can claim it without one is refused, and a staged file edited after
// the fact is too. The unmodified plan publishes (negative control).
func TestPublishStageAcceptsMirroredOnlyOnTheRecord(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(e map[string]any)
		reason string
	}{
		{"unmodified", func(map[string]any) {}, ""},
		{"verification not recorded", func(e map[string]any) { e["mirror"].(map[string]any)["verified"] = false }, "does not record that"},
		{"digest of another file", func(e map[string]any) { e["mirror"].(map[string]any)["digest"] = digestOf([]byte("x")) }, "verified digest"},
		{"source not a registry", func(e map[string]any) { e["mirror"].(map[string]any)["from"] = "https://dist.example" }, "not an oci://"},
		{"verdict without a record", func(e map[string]any) { delete(e, "mirror") }, "disagree"},
		{"record on another verdict", func(e map[string]any) { e["test"] = "pass" }, "disagree"},
		{"control character in the record", func(e map[string]any) { e["mirror"].(map[string]any)["from"] = mirrorSeed + "\n" }, "control character"},
		{"host-built", func(e map[string]any) { e["bootstrap"] = "1" }, "not a verified sovereign"},
		{"not sovereign", func(e map[string]any) { e["sovereign"] = "0" }, "not a verified sovereign"},
	}
	for _, c := range mutations {
		t.Run(c.name, func(t *testing.T) {
			r := newMirrorStageRig(t)
			r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
			if code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
				"--mirror-from", mirrorSeed, "--require-origin"); code != 0 {
				t.Fatalf("stage code=%d\n%s", code, r.h.errb.String())
			}
			plan := readPlan(t, r.h.artifacts)
			c.mutate(planEntries(plan)[0].(map[string]any))
			b, _ := json.Marshal(plan)
			if err := os.WriteFile(filepath.Join(r.h.artifacts, stagePlanName), b, 0o644); err != nil {
				t.Fatal(err)
			}
			code, _, errb := r.publishStage("--to", stageDist, "--sign", r.key)
			if c.reason == "" {
				if code != 0 || len(r.pushes) != 1 {
					t.Fatalf("the genuine plan was refused: code=%d %s", code, errb)
				}
				return
			}
			if code == 0 || len(r.pushes) != 0 {
				t.Errorf("code=%d pushes=%d, want a refusal", code, len(r.pushes))
			}
			if !strings.Contains(errb, c.reason) {
				t.Errorf("refusal lacks %q: %s", c.reason, errb)
			}
		})
	}
	t.Run("staged file edited after verification", func(t *testing.T) {
		r := newMirrorStageRig(t)
		r.serve(t, r.tarball, r.tarball, sovereignSource, nil)
		if code := r.h.run(t, "--stage-only", "--recipes", "lib.org", "--to", stageDist,
			"--mirror-from", mirrorSeed, "--require-origin"); code != 0 {
			t.Fatalf("stage code=%d", code)
		}
		p := filepath.Join(r.h.artifacts, "lib.org", "linux", "x86-64", "v1.0.tar.gz")
		if err := os.WriteFile(p, stageTarball(t, "swapped"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := r.publishStage("--to", stageDist, "--sign", r.key); code == 0 || len(r.pushes) != 0 {
			t.Errorf("code=%d pushes=%d", code, len(r.pushes))
		}
	})
}
