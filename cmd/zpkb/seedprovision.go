package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-zpkg/artifact"
)

// maxProvisionEnv bounds the environment text one closure may produce.
const maxProvisionEnv = 4 << 20

// seedProvisioner composes the build environment of a seeded build in the
// FACTORY, so the generated script never has to ask zpkx for packages (zpkx
// refuses that under a seed, by design). Every closure is installed by a zpkx
// started here with the seed flags, so everything it fetches is verified and
// recorded in a ledger the factory owns; the entries are merged into the set the
// plan signs. The ledger a zpkx writes is private to one call and read back
// here. LIMIT: the directory is a 0700 temporary of the factory's user, so it
// keeps out a recipe running as another user and out of a chroot that does not
// share the factory's temp; code running as the SAME user (or root) concurrently
// could still write there. What is checked about that: a per-call ledger must not
// exist before its call, and the plan-phase ledger must still be empty (Verify)
// when the entries are signed.
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
	ledger := filepath.Join(p.dir, fmt.Sprintf("ledger-%d", p.calls))
	// Only "does not exist" is absence: any other answer (an unreadable or
	// replaced directory) is a ledger path this process cannot vouch for.
	if _, err := os.Lstat(ledger); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return "", fmt.Errorf("the ledger %s already exists before its call: refusing a file this process did not create", ledger)
		}
		return "", fmt.Errorf("cannot tell whether the ledger %s exists before its call: %w", ledger, err)
	}
	args := []string{"--seed-from", p.from, "--seed-ledger", ledger}
	for _, s := range specs {
		args = append(args, "+"+s)
	}
	cmd := exec.Command(p.zpkx, args...)
	cmd.Env = append(envWithout(os.Environ(), "ZPKX_SEEDED"), "CLICOLOR_FORCE=1")
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxProvisionEnv}
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		return "", err
	}
	if _, err := os.Stat(ledger); err == nil {
		es, err := artifact.ReadSeedLedger(ledger)
		if err != nil {
			return "", err
		}
		p.add(es)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("cannot read the ledger %s the call wrote: %w", ledger, err)
	}
	return out.String(), nil
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
