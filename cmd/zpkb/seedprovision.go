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
	"slices"
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

	// setReadDeadline is the pipe's deadline; a pipe that cannot have one would
	// leave the drain waiting for a descendant that holds the write end.
	setReadDeadline = func(f *os.File, t time.Time) error { return f.SetReadDeadline(t) }
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
// read lines out of it or append to it, and the same process can write the
// store. The cross-check is a detector of accidents (a zpkx that died, a lost
// or doubled record) and of a forgery by a writer that does not control the
// store; it is NOT a barrier against the same uid. Each record must name the
// registry asked for, a valid project name and keys of the trust set, and
// agree with any other line for the same artifact; it is checked against the
// seed prefixes found by walking the store (the marker the installer writes
// there carries the signed digest); a record naming a prefix that is not staged,
// and a staged prefix no record names (also one staged between two calls), are
// both refused, and so is a read that the deadline ended. The plan-phase
// ledger, a file the artifact package writes in the factory's 0700 temporary,
// must still be empty (Verify) when the entries are signed.
type seedProvisioner struct {
	zpkx string
	from string // the seed registry, as $ZPKX_SEEDED names it
	dir  string // private directory for per-call ledgers

	pick    sync.Mutex // serialises the registry swap of inSeed
	mu      sync.Mutex
	entries []artifact.SeedEntry
	seen    map[string]bool
	calls   int

	// accounted is every marker of the store that a record names, or that was
	// there when the provisioner was made: a marker outside it is a seed nobody
	// recorded.
	accounted map[string]string
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
	p := &seedProvisioner{zpkx: zpkx, from: from, dir: dir, seen: map[string]bool{}, accounted: stagedSeeds(artifact.Dir())}
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
	defer pw.Close()
	if err := setReadDeadline(pr, time.Time{}); err != nil {
		return "", fmt.Errorf("seed ledger: this pipe has no read deadline, so a descendant holding it could hang the build: %w", err)
	}
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
	if derr := setReadDeadline(pr, time.Now().Add(drainGrace)); derr != nil {
		// Not waited for: got is buffered, and the deferred Close ends the drain.
		return "", fmt.Errorf("seed ledger: the read deadline could not be set: %w", derr)
	}
	l := <-got
	if err != nil {
		return "", err
	}
	if l.err != nil {
		return "", l.err
	}
	es, err := parseSeedLedger(l.b, p.from)
	if err != nil {
		return "", err
	}
	after := stagedSeeds(artifact.Dir())
	if err := crossCheckLedger(artifact.Dir(), es, p.accounted, after); err != nil {
		return "", err
	}
	for m, d := range after {
		p.accounted[m] = d
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

// maxStoreDepth bounds the walk of the store: a project name has at most 8
// segments (artifact.ValidateProjectName), and the build directory is one more.
const maxStoreDepth = 9

// isBuildDirName is a directory named like a build: v, a digit, and the "-h"
// that precedes the hash of every real build directory (artifact's
// StoreBuildDirName). Such a directory is never entered (it holds an installed
// tree), so a project segment named like one could not be located. A plain
// segment like the "v2" of pcre.org/v2 has no hash and is a project segment.
func isBuildDirName(n string) bool {
	return len(n) > 1 && n[0] == 'v' && n[1] >= '0' && n[1] <= '9' && strings.Contains(n, "-h")
}

func hasBuildDirSegment(project string) bool {
	for _, s := range strings.Split(project, "/") {
		if isBuildDirName(s) {
			return true
		}
	}
	return false
}

// stagedSeeds is every seed marker the store holds, as path -> the digest the
// installer recorded in it, found by walking the store (any depth a project
// name can have), not by patterns of fixed depth. Only real directories are
// entered: the symlinked aliases of a build are the same tree. A directory that
// carries a marker is never entered. An unreadable marker maps to "": it is
// staged, and no record can match it.
func stagedSeeds(dir string) map[string]string {
	out := map[string]string{}
	walkSeeds(dir, 0, out)
	return out
}

func walkSeeds(p string, depth int, out map[string]string) {
	if depth > maxStoreDepth {
		return
	}
	es, _ := os.ReadDir(p) // an absent or unreadable directory holds nothing to find
	for _, e := range es {
		if !e.IsDir() {
			continue
		}
		c := filepath.Join(p, e.Name())
		if d, seeded, err := artifact.IsSeedPrefix(c); seeded || err != nil {
			out[filepath.Join(c, artifact.SeedMarkerName)] = d
			continue
		}
		if !isBuildDirName(e.Name()) {
			walkSeeds(c, depth+1, out)
		}
	}
}

// seedPrefixOf is where the installer puts the artifact a record names: the
// directory is named from the content digest, and carries the marker. The
// project is a validated name here, and joined, never cleaned onto another.
func seedPrefixOf(dir string, e artifact.SeedEntry) string {
	v := artifact.ParseVer(e.Version)
	return artifact.StoreBuildPrefix(dir, e.Project, v, artifact.StoreHash(v, e.Digest, ""))
}

// crossCheckLedger refuses a ledger that disagrees with what the call staged.
// Every record must name a prefix the store holds, marked with that record's
// digest (an injected record has none); and every marker that appeared during
// the store holds that no earlier call accounted for must be named by a record
// (a removed record, a ledger the writer never reached, or a seed staged
// between two calls, leaves one unaccounted for).
func crossCheckLedger(dir string, es []artifact.SeedEntry, accounted, after map[string]string) error {
	named := map[string]bool{}
	for _, e := range es {
		m := filepath.Join(seedPrefixOf(dir, e), artifact.SeedMarkerName)
		if d, ok := after[m]; !ok || d != e.Digest {
			return fmt.Errorf("seed ledger names %s %s (%s), which the call did not stage: refusing a record nothing installed", e.Project, e.Version, e.Digest)
		}
		named[m] = true
	}
	for m := range after {
		if _, had := accounted[m]; !had && !named[m] {
			return fmt.Errorf("seed ledger has no record of %s, which the call staged: refusing a ledger that lost an entry", filepath.Dir(m))
		}
	}
	return nil
}

// trustedKeyIDs is the set of key ids the seed trust set holds: a record may
// name no other key as having signed what it installed.
func trustedKeyIDs() map[string]bool {
	ids := map[string]bool{}
	for _, s := range artifact.SeedTrustSet().Signers {
		ids[s.KeyID()] = true
	}
	return ids
}

// sameRecord is whether two lines with one (project, version, digest) say the
// same thing: the first of them must not win over a second that disagrees.
func sameRecord(a, b artifact.SeedEntry) bool {
	return a.Source == b.Source && slices.Equal(a.Signers, b.Signers) && slices.Equal(a.Keys, b.Keys)
}

// parseSeedLedger is artifact.ReadSeedLedger over bytes already read: a line
// that is not an entry is an error, never skipped, and the entries come back
// in the same canonical order. A record is bound to what this provisioner
// asked for: it names the registry it was given (from), a project name that is
// one, and keys the trust set holds; two lines for one artifact must agree.
func parseSeedLedger(b []byte, from string) ([]artifact.SeedEntry, error) {
	trusted := trustedKeyIDs()
	seen := map[string]artifact.SeedEntry{}
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
		var rest json.RawMessage
		if err := dec.Decode(&rest); err != io.EOF {
			return nil, fmt.Errorf("seed ledger line %d: bytes after the entry", i+1)
		}
		if e.Project == "" || e.Version == "" || e.Digest == "" {
			return nil, fmt.Errorf("seed ledger line %d: an entry names a project, a version and a digest", i+1)
		}
		if err := artifact.ValidateProjectName(e.Project); err != nil {
			return nil, fmt.Errorf("seed ledger line %d: %w", i+1, err)
		}
		if hasBuildDirSegment(e.Project) {
			return nil, fmt.Errorf("seed ledger line %d: project %q has a segment the store check cannot tell from a build directory", i+1, e.Project)
		}
		if e.Source != from {
			return nil, fmt.Errorf("seed ledger line %d: source %q is not the seed registry %q", i+1, e.Source, from)
		}
		sort.Strings(e.Signers)
		sort.Strings(e.Keys)
		for _, k := range e.Keys {
			if !trusted[k] {
				return nil, fmt.Errorf("seed ledger line %d: key %q is not in the seed trust set", i+1, k)
			}
		}
		k := provisionKey(e)
		if first, ok := seen[k]; ok {
			if !sameRecord(first, e) {
				return nil, fmt.Errorf("seed ledger line %d: two records for %s %s disagree", i+1, e.Project, e.Version)
			}
			continue
		}
		seen[k] = e
		out = append(out, e)
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
