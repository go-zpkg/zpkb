package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
// here, so a recipe cannot add to, or remove from, what is signed.
type seedProvisioner struct {
	zpkx string
	from string // the seed registry, as $ZPKX_SEEDED names it
	dir  string // private directory for per-call ledgers

	mu      sync.Mutex
	entries []artifact.SeedEntry
	seen    map[string]bool
	calls   int
}

func newSeedProvisioner(zpkx, from string, base []artifact.SeedEntry) (*seedProvisioner, error) {
	if from == "" {
		return nil, errors.New("seed provisioning needs the seed registry ($ZPKX_SEEDED)")
	}
	dir, err := os.MkdirTemp("", "zpkb-seed-provision-")
	if err != nil {
		return nil, err
	}
	p := &seedProvisioner{zpkx: zpkx, from: from, dir: dir, seen: map[string]bool{}}
	p.add(base)
	return p, nil
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
