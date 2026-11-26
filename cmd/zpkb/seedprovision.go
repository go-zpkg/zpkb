package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-zpkg/artifact"
)

// maxProvisionEnv bounds the environment text one closure may produce.
const maxProvisionEnv = 4 << 20

// ledgerFD is the descriptor number the ledger pipe has in the child: the first
// extra descriptor of exec.Cmd. zpkx is told the NUMBER (--seed-ledger-fd) and
// writes to that descriptor itself; there is no path to look up, so a build
// chroot with no /dev/fd, or with a /dev/fd somebody made, changes nothing.
const ledgerFD = "3"

// Seams, so the two ways a pipe can be unavailable are testable.
var (
	seedPipe = seedPipeSupported
	newPipe  = os.Pipe
)

// seedProvisioner composes the build environment of a seeded build in the
// FACTORY, so the generated script never has to ask zpkx for packages (zpkx
// refuses that under a seed, by design). Every closure is installed by a zpkx
// started here with the seed flags, so everything it fetches is verified and
// recorded in a ledger the factory owns; the entries are merged into the set the
// plan signs. The ledger a zpkx writes is a pipe private to one call, handed
// over as a descriptor and drained here: no file exists in a directory for
// another process to rewrite between zpkx's write and the read-back.
//
// WHAT HOLDS, AND WHAT DOES NOT. The pipe is not a defence against a process of
// the factory's own user, or root: on Linux /proc/<pid>/fd lets such a process
// read lines out of it or append to it. So the ledger is not trusted for what
// it says: every record is cross-checked against the seed prefixes the call
// actually staged in the store (the marker the installer writes there carries
// the signed digest), a record naming a prefix that is not staged and a staged
// prefix with no record are both refused, and so is a read that the deadline
// ended. What the cross-check cannot cover is a writer who can also forge the
// store's markers; that is the store's own trust, not this ledger's. The
// plan-phase ledger, a file the artifact package writes in the factory's 0700
// temporary, must still be empty (Verify) when the entries are signed.
type seedProvisioner struct {
	zpkx string
	from string // the seed registry, as $ZPKX_SEEDED names it
	dir  string // private directory for per-call ledgers

	pick    sync.Mutex // serialises the registry swap of inSeed
	mu      sync.Mutex
	entries []artifact.SeedEntry
	seen    map[string]bool
	calls   int
}

func newSeedProvisioner(zpkx, from string, base []artifact.SeedEntry) (*seedProvisioner, error) {
	if from == "" {
		return nil, errors.New("seed provisioning needs the seed registry ($ZPKX_SEEDED)")
	}
	if err := checkSeedUpstream(artifact.UpstreamDist); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "zpkb-seed-provision-")
	if err != nil {
		return nil, err
	}
	// Plan-phase version resolution reads the seed registry's signed index
	// (WithSeedSource insists on a ledger file being set; a listing installs
	// nothing, so it stays empty).
	artifact.SetSeedLedgerFile(filepath.Join(dir, "resolve-ledger"))
	p := &seedProvisioner{zpkx: zpkx, from: from, dir: dir, seen: map[string]bool{}}
	p.add(base)
	return p, nil
}

// checkSeedUpstream refuses any upstream dist under a seed. The versions of a
// seed pass come from the pinned, signed seed registry; an upstream dist
// (dist.pkgx.dev, or any other) is an unsigned source the seed design forbids.
func checkSeedUpstream(upstream string) error {
	if upstream == "" || upstream == "none" {
		return nil
	}
	return fmt.Errorf("a seed is in force and ZPKG_UPSTREAM_DIST=%s names an unsigned upstream: "+
		"versions resolve from the pinned seed registry only", upstream)
}

// inSeed runs fn with the artifact package reading the seed registry, so a
// version is resolved from the signed index and never from the factory's own
// dist (which does not carry the seed's packages).
func (p *seedProvisioner) inSeed(fn func() error) error {
	p.pick.Lock()
	defer p.pick.Unlock()
	return artifact.WithSeedSource(p.from, fn)
}

// Pick wraps a version resolver so it answers from the seed registry.
func (p *seedProvisioner) Pick(f func(project, constraint string) (string, error)) func(string, string) (string, error) {
	return func(project, constraint string) (v string, err error) {
		if e := p.inSeed(func() error { v, err = f(project, constraint); return err }); e != nil {
			return "", e
		}
		return v, nil
	}
}

func provisionKey(e artifact.SeedEntry) string {
	return e.Project + "\x00" + e.Version + "\x00" + e.Digest
}

func (p *seedProvisioner) add(es []artifact.SeedEntry) {
	for _, e := range es {
		if k := provisionKey(e); !p.seen[k] {
			p.seen[k] = true
			p.entries = append(p.entries, e)
		}
	}
}

// Entries is every seed artifact the build environment was made of: the
// snapshot taken at the start plus what each closure installed.
func (p *seedProvisioner) Entries() []artifact.SeedEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]artifact.SeedEntry(nil), p.entries...)
}

// verifyProvisioner is a seam: the real check needs something to have written
// into the provisioner's private directory while the factory runs.
var verifyProvisioner = (*seedProvisioner).Verify

// Verify asserts the plan-phase ledger is still empty: a version listing
// installs nothing, so entries in it mean something other than this process
// wrote there. Called before the entries are signed.
func (p *seedProvisioner) Verify() error {
	st, err := os.Lstat(filepath.Join(p.dir, "resolve-ledger"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !st.Mode().IsRegular() || st.Size() != 0:
		return errors.New("the plan-phase seed ledger is not empty: something other than a version listing wrote to the provisioner's directory")
	}
	return nil
}

// Close removes the private ledgers.
func (p *seedProvisioner) Close() error { return os.RemoveAll(p.dir) }

// Provision installs specs from the seed and returns the environment text.
func (p *seedProvisioner) Provision(specs []string) (string, error) {
	if len(specs) == 0 {
		return "", nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if err := seedPipe(); err != nil {
		return "", err
	}
	// The ledger is a pipe, not a file: there is no path in any directory for
	// code of the same user to rewrite between zpkx's write and the read-back.
	// The child writes to descriptor 3 (--seed-ledger-fd), never to a path.
	pr, pw, err := newPipe()
	if err != nil {
		return "", err
	}
	defer pr.Close()
	before := stagedSeeds(artifact.Dir())
	args := []string{"--seed-from", p.from, "--seed-ledger-fd", ledgerFD}
	for _, s := range specs {
		args = append(args, "+"+s)
	}
	cmd := exec.Command(p.zpkx, args...)
	cmd.Env = append(envWithout(os.Environ(), "ZPKX_SEEDED"), "CLICOLOR_FORCE=1")
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxProvisionEnv}
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	cmd.ExtraFiles = []*os.File{pw}
	got := make(chan ledgerRead, 1)
	go func() { b, err := drainLedger(pr); got <- ledgerRead{b, err} }()
	err = cmd.Run()
	pw.Close()
	// A descendant may still hold the write end: what the call wrote is already
	// in the pipe, so stop reading after a short grace instead of waiting for EOF.
	pr.SetReadDeadline(time.Now().Add(drainGrace))
	l := <-got
	if err != nil {
		return "", err
	}
	if l.err != nil {
		return "", l.err
	}
	es, err := parseSeedLedger(l.b)
	if err != nil {
		return "", err
	}
	if err := crossCheckLedger(artifact.Dir(), es, before, stagedSeeds(artifact.Dir())); err != nil {
		return "", err
	}
	p.add(es)
	return out.String(), nil
}

// drainGrace is how long the read of a call's ledger goes on after the call
// ended, for a descendant that kept the pipe open.
const drainGrace = 200 * time.Millisecond

type ledgerRead struct {
	b   []byte
	err error
}

// errLedgerNotClosed is a read that the deadline ended: something still holds
// the write end after the call ended, so what was read is not known to be the
// whole ledger.
var errLedgerNotClosed = errors.New("seed ledger: the call ended and something still holds the ledger open; what was read is not known to be all of it")

// drainLedger reads the pipe until EOF. It keeps reading past the bound (and
// drops it) so a writer is never blocked on a full pipe. A read ended by the
// deadline is an error, never a short ledger accepted as complete.
func drainLedger(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, artifact.MaxSeedLedgerBytes+1))
	if err == nil && len(b) > artifact.MaxSeedLedgerBytes {
		_, err = io.Copy(io.Discard, r)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			err = nil
		}
		return nil, errors.Join(err, fmt.Errorf("seed ledger: larger than %d bytes", artifact.MaxSeedLedgerBytes))
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, errLedgerNotClosed
	}
	return b, err
}

// seedMarkerGlobs are the depths a project name can have under the store.
var seedMarkerGlobs = []string{
	"*/v*/" + artifact.SeedMarkerName,
	"*/*/v*/" + artifact.SeedMarkerName,
	"*/*/*/v*/" + artifact.SeedMarkerName,
}

// stagedSeeds is every seed marker the store holds, as path -> the digest the
// installer recorded in it. An unreadable marker maps to "": it is staged, and
// no record can match it.
func stagedSeeds(dir string) map[string]string {
	out := map[string]string{}
	for _, g := range seedMarkerGlobs {
		ms, _ := filepath.Glob(filepath.Join(dir, g)) // the patterns are constant: no error
		for _, m := range ms {
			d, _, _ := artifact.IsSeedPrefix(filepath.Dir(m))
			out[m] = d
		}
	}
	return out
}

// seedPrefixOf is where the installer puts the artifact a record names: the
// directory is named from the content digest, and carries the marker.
func seedPrefixOf(dir string, e artifact.SeedEntry) string {
	v := artifact.ParseVer(e.Version)
	return artifact.StoreBuildPrefix(dir, e.Project, v, artifact.StoreHash(v, e.Digest, ""))
}

// crossCheckLedger refuses a ledger that disagrees with what the call staged.
// Every record must name a prefix the store holds, marked with that record's
// digest (an injected record has none); and every marker that appeared during
// the call must be named by a record (a removed record, or a ledger the writer
// never reached, leaves one unaccounted for).
func crossCheckLedger(dir string, es []artifact.SeedEntry, before, after map[string]string) error {
	named := map[string]bool{}
	for _, e := range es {
		m := filepath.Join(seedPrefixOf(dir, e), artifact.SeedMarkerName)
		if d, ok := after[m]; !ok || d != e.Digest {
			return fmt.Errorf("seed ledger names %s %s (%s), which the call did not stage: refusing a record nothing installed", e.Project, e.Version, e.Digest)
		}
		named[m] = true
	}
	for m := range after {
		if _, had := before[m]; !had && !named[m] {
			return fmt.Errorf("seed ledger has no record of %s, which the call staged: refusing a ledger that lost an entry", filepath.Dir(m))
		}
	}
	return nil
}

// parseSeedLedger is artifact.ReadSeedLedger over bytes already read: a line
// that is not an entry is an error, never skipped, and the entries come back
// in the same canonical order.
func parseSeedLedger(b []byte) ([]artifact.SeedEntry, error) {
	seen := map[string]bool{}
	var out []artifact.SeedEntry
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e artifact.SeedEntry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("seed ledger line %d: %w", i+1, err)
		}
		if e.Project == "" || e.Version == "" || e.Digest == "" {
			return nil, fmt.Errorf("seed ledger line %d: an entry names a project, a version and a digest", i+1)
		}
		sort.Strings(e.Signers)
		if k := provisionKey(e); !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Digest < b.Digest
	})
	return out, nil
}

// envWithout drops every NAME=... entry of env.
func envWithout(env []string, name string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// limitWriter fails once more than n bytes are written.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(b []byte) (int, error) {
	if len(b) > l.n {
		return 0, fmt.Errorf("environment larger than %d bytes", maxProvisionEnv)
	}
	l.n -= len(b)
	return l.w.Write(b)
}
