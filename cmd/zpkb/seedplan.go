package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/moustache"
)

// A SEED PASS builds with another registry's artifacts as the BUILD
// ENVIRONMENT (zpkx --seed-from; artifact.WithSeedSource). The seed is verified
// by that machinery and recorded in a ledger file; this file is the other half:
// the factory carries the ledger into the stage plan, publish-stage writes it
// into the provenance (as materials, with digests) and into the signed claim,
// and promotion refuses an artifact that carries it.
//
// ⛔ THE FACT MUST NOT BE ABLE TO GO MISSING. A seed-built artifact signed with
// no mention of its seed is indistinguishable from one built from our own
// outputs — which is exactly what the second pass exists to be. So the
// environment and the flag must agree: a seed in force with no ledger flag is
// refused (the artifacts would be unmarked), and a ledger flag with no seed in
// force is refused (the ledger would be a claim about nothing).

// checkSeedFlags is the consistency rule between --seed-ledger, the seed zpkx
// put in the environment (seedFrom is $ZPKX_SEEDED, a marker zpkx never reads), --stage-only and
// --mirror-from.
func checkSeedFlags(ledger, seedFrom string, stageOnly bool, mirrorFrom string) error {
	switch {
	case ledger == "" && seedFrom == "":
		return nil
	case ledger != "" && seedFrom == "":
		return errors.New("--seed-ledger records a seed, and no seed is in force (run it under `zpkx --seed-from <registry>`)")
	case ledger == "":
		return errors.New("a seed is in force ($ZPKX_SEEDED) and --seed-ledger is not given: the artifacts would be signed without naming their seed")
	case !stageOnly:
		return errors.New("--seed-ledger needs --stage-only: the plan carries the seed to `zpkb publish-stage`, which signs it")
	case mirrorFrom != "":
		return errors.New("--seed-ledger with --mirror-from: a seed pass builds, it does not copy")
	}
	return nil
}

// applySeed reads the ledger and records it on the plan. An absent or empty
// ledger is an error (a seed pass that installed nothing from its seed is not
// what was asked for). A plan already carrying a seed accepts a ledger that
// only GROWS — chunks of one pass share one ledger file — and refuses one that
// lost an entry. What it recorded is reported on out.
func applySeed(p *stagePlan, ledgerPath string, out io.Writer) error {
	snap, err := snapshotSeed(ledgerPath, "")
	if err != nil {
		return err
	}
	return applySeedEntries(p, snap, out)
}

// snapshotSeed reads the ledger ONCE, bounded (artifact.ReadSeedLedger), and
// refuses an empty one. It is called at the start of a run, before any recipe
// has executed: the ledger lives where a recipe can write, so what is signed is
// what the seed installation left, never what the file says by the time the
// recipes are done. A non-empty wantDigest is the digest the outside of the
// build recorded for that ledger; a ledger that does not match it is refused.
func snapshotSeed(ledgerPath, wantDigest string) ([]artifact.SeedEntry, error) {
	es, err := artifact.ReadSeedLedger(ledgerPath)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, fmt.Errorf("seed ledger %s is empty: the pass installed nothing from its seed", ledgerPath)
	}
	if got := artifact.SeedLedgerDigest(es); wantDigest != "" && got != wantDigest {
		return nil, fmt.Errorf("seed ledger %s has digest sha256:%s, the build recorded sha256:%s: refusing a ledger that changed", ledgerPath, got, wantDigest)
	}
	return es, nil
}

// applySeedEntries records an already-read ledger on the plan; see applySeed.
func applySeedEntries(p *stagePlan, es []artifact.SeedEntry, out io.Writer) error {
	if old := p.Seed; old != nil {
		have := map[string]bool{}
		for _, e := range es {
			have[e.Project+"\x00"+e.Version+"\x00"+e.Digest] = true
		}
		for _, e := range old.Entries {
			if !have[e.Project+"\x00"+e.Version+"\x00"+e.Digest] {
				return fmt.Errorf("the plan's seed names %s %s (%s), which this ledger no longer has", e.Project, e.Version, e.Digest)
			}
		}
	}
	seed := &stageSeed{Digest: artifact.SeedLedgerDigest(es), Entries: es}
	p.Seed = seed
	fmt.Fprintf(out, "seed: %d artifact(s) of the seed registry were the build environment (ledger sha256:%s) — named in the provenance, never promotable\n", len(seed.Entries), seed.Digest)
	return nil
}

// refuseSeededPrefixes is the stage-time half of the seed marker: a build that
// stages itself as UNSEEDED (seeded == false) while any prefix it was built
// from carries the installer's marker is refused, naming the dependency. The
// marker is written by the installer, so a build that never saw the seed flag
// cannot have left the fact out. Under a seed, marked prefixes are expected.
func refuseSeededPrefixes(env []moustache.Dep, seeded bool) error {
	if seeded {
		return nil
	}
	for _, d := range env {
		if d.Path == "" {
			continue
		}
		digest, marked, err := artifact.IsSeedPrefix(d.Path)
		if err != nil {
			return fmt.Errorf("%s %s: cannot tell whether its prefix came from a seed: %w", d.Project, d.Version, err)
		}
		if marked {
			return fmt.Errorf("%s %s was installed from a seed (%s) and this build is staged unseeded: pass --seed-ledger or rebuild it", d.Project, d.Version, digest)
		}
	}
	return nil
}

// checkPlanSeed is run on the plan a stage already holds, before this run adds
// to it: one pass has one seed, so a seeded run does not extend a plan of
// unseeded artifacts and an unseeded run does not extend a seeded one.
func checkPlanSeed(p *stagePlan, seeded bool) error {
	switch {
	case seeded && p.Seed == nil && len(p.Artifacts) > 0:
		return errors.New("the stage already holds unseeded artifacts: one pass has one seed")
	case !seeded && p.Seed != nil:
		return errors.New("the stage holds a seeded plan and this run has no seed: one pass has one seed")
	}
	return nil
}
