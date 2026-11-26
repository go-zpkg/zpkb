//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/artifact"
)

// fakeZpkx writes a script that stands in for zpkx ONLY for the unit tests of
// the provisioner's plumbing; the real binaries are exercised by the end-to-end
// test (seedprovision_e2e_test.go).
func fakeZpkx(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "zpkx")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The per-call ledgers live in a directory recipe code of the same user could
// write to while a build runs. A ledger that exists before its zpkx call is
// refused, and the plan-phase ledger, which must stay empty (a listing installs
// nothing), is asserted empty before the entries are signed.
func TestProvisionerRefusesPlantedLedgersAndANonEmptyPlanLedger(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	p, err := newSeedProvisioner(fakeZpkx(t, "exit 0\n"), "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Verify(); err != nil {
		t.Fatalf("a fresh provisioner: %v", err)
	}
	resolve := filepath.Join(p.dir, "resolve-ledger")
	if err := os.WriteFile(resolve, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != nil {
		t.Errorf("an empty plan-phase ledger: %v", err)
	}
	if err := os.WriteFile(resolve, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a plan-phase ledger with entries: %v", err)
	}
	if err := os.Remove(resolve); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(resolve, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err == nil {
		t.Error("a plan-phase ledger that is a directory was accepted")
	}
	// A private directory that stopped being one: the ledger cannot be read, which
	// is not the same as it being absent.
	bad := &seedProvisioner{dir: filepath.Join(t.TempDir(), "f")}
	if err := os.WriteFile(bad.dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(); err == nil || strings.Contains(err.Error(), "not empty") {
		t.Errorf("an unreadable plan-phase ledger: %v", err)
	}
}

const entryLine = `{"project":"p","version":"1.0.0","digest":"sha256:d","signers":[],"keys":[],"source":"s"}`

// The window between zpkx's write and the read-back: a process of the same user
// that tries to edit the ledger in it finds no file to edit (the ledger is a
// pipe, there is nothing in the factory's directory), and an attempt to wipe it
// through the descriptor it inherited does not remove what was written.
func TestProvisionerLedgerHasNoFileToEditAndCannotBeWiped(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	var p *seedProvisioner
	dirOf := filepath.Join(t.TempDir(), "dir")
	z := fakeZpkx(t, "printf '%s\\n' '"+entryLine+"' >> \"$4\"\n"+
		": > \"$4\"\n"+ // a recipe truncating the ledger
		"D=$(cat '"+dirOf+"')\n"+
		"for f in \"$D\"/*; do case \"$f\" in */resolve-ledger) ;; *) [ -e \"$f\" ] && exit 5;; esac; done\nexit 0\n")
	p, err := newSeedProvisioner(z, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := os.WriteFile(dirOf, []byte(p.dir), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision([]string{"a"}); err != nil {
		t.Fatalf("a file appeared in the directory, or the call failed: %v", err)
	}
	if es := p.Entries(); len(es) != 1 || es[0].Project != "p" {
		t.Errorf("the entry written before the wipe attempt was lost: %+v", es)
	}
}

// A descendant that keeps the pipe open after the call ended does not hang the
// factory.
func TestProvisionerDoesNotWaitForADescendantHoldingTheLedger(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	z := fakeZpkx(t, "printf '%s\\n' '"+entryLine+"' >> \"$4\"\n(sleep 3 >/dev/null 2>&1 &)\n")
	p, err := newSeedProvisioner(z, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := time.Now()
	if _, err := p.Provision([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the read waited for a descendant that held the pipe")
	}
	if len(p.Entries()) != 1 {
		t.Errorf("entries = %+v", p.Entries())
	}
}

// A call that writes more than a ledger may hold is refused, and is not left
// blocked on a full pipe.
func TestProvisionerRefusesAnOversizedLedger(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	z := fakeZpkx(t, "head -c 17000000 /dev/zero | tr '\\0' 'x' >> \"$4\"\n")
	p, err := newSeedProvisioner(z, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	done := make(chan error, 1)
	go func() {
		_, err := p.Provision([]string{"a"})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("an oversized ledger: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the call stayed blocked on a full pipe")
	}
}

type failingReader struct {
	first []byte
	end   error // what the read ends with; "boom" when nil
}

func (f *failingReader) Read(b []byte) (int, error) {
	if len(f.first) > 0 {
		n := copy(b, f.first)
		f.first = f.first[n:]
		return n, nil
	}
	if f.end != nil {
		return 0, f.end
	}
	return 0, errors.New("boom")
}

func TestDrainLedgerReportsAReadFailure(t *testing.T) {
	if _, err := drainLedger(&failingReader{first: []byte("x")}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("a failing pipe: %v", err)
	}
	big := make([]byte, artifact.MaxSeedLedgerBytes+10)
	_, err := drainLedger(&failingReader{first: big})
	if err == nil || !strings.Contains(err.Error(), "larger than") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("an oversized ledger behind a failing pipe: %v", err)
	}
	r := deadlineReader{}
	if b, err := drainLedger(r); err != nil || len(b) != 0 {
		t.Errorf("a deadline is the end of the read, not a failure: %q, %v", b, err)
	}
	if _, err := drainLedger(&failingReader{first: big, end: os.ErrDeadlineExceeded}); err == nil || strings.Contains(err.Error(), "deadline") {
		t.Errorf("a deadline after an oversized ledger: %v", err)
	}
}

type deadlineReader struct{}

func (deadlineReader) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

func TestProvisionerRefusesWithoutAPipe(t *testing.T) {
	z := fakeZpkx(t, ": > \"$HOME/ran-never\"\n")
	p := &seedProvisioner{zpkx: z, from: "oci://seed", seen: map[string]bool{}}
	defer func(a func() error, b func() (*os.File, *os.File, error)) { seedPipe, newPipe = a, b }(seedPipe, newPipe)
	seedPipe = func() error { return errors.New("no /dev/fd") }
	if _, err := p.Provision([]string{"a"}); err == nil || !strings.Contains(err.Error(), "no /dev/fd") {
		t.Errorf("a system without /dev/fd: %v", err)
	}
	seedPipe = func() error { return nil }
	newPipe = func() (*os.File, *os.File, error) { return nil, nil, errors.New("no pipes") }
	if _, err := p.Provision([]string{"a"}); err == nil || !strings.Contains(err.Error(), "no pipes") {
		t.Errorf("no pipe could be made: %v", err)
	}
}

func TestParseSeedLedger(t *testing.T) {
	ord := `{"project":"p","version":"%s","digest":"%s"}` + "\n"
	in := strings.NewReplacer("%s", "X").Replace("") +
		strings.Replace(strings.Replace(ord, "%s", "2", 1), "%s", "d1", 1) +
		strings.Replace(strings.Replace(ord, "%s", "1", 1), "%s", "d2", 1) +
		strings.Replace(strings.Replace(ord, "%s", "1", 1), "%s", "d1", 1)
	if es, err := parseSeedLedger([]byte(in)); err != nil || len(es) != 3 ||
		es[0].Version != "1" || es[0].Digest != "d1" || es[1].Digest != "d2" || es[2].Version != "2" {
		t.Errorf("ordered by project, version, digest: %+v, %v", es, err)
	}
	two := entryLine + "\n\n" + strings.Replace(entryLine, `"p"`, `"a"`, 1) + "\n" + entryLine + "\n"
	es, err := parseSeedLedger([]byte(two))
	if err != nil || len(es) != 2 || es[0].Project != "a" || es[1].Project != "p" {
		t.Errorf("sorted and deduplicated: %+v, %v", es, err)
	}
	if es, err := parseSeedLedger(nil); err != nil || len(es) != 0 {
		t.Errorf("an empty ledger: %+v, %v", es, err)
	}
	for name, in := range map[string]string{
		"not json":      "notjson\n",
		"unknown field": `{"project":"p","version":"1","digest":"d","extra":1}` + "\n",
		"no digest":     `{"project":"p","version":"1"}` + "\n",
		"no project":    `{"version":"1","digest":"d"}` + "\n",
		"no version":    `{"project":"p","digest":"d"}` + "\n",
	} {
		if _, err := parseSeedLedger([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProvisionerRecordsWhatEachClosureInstalled(t *testing.T) {
	// $5 is the ledger path: arguments are --seed-from X --seed-ledger L +spec...
	z := fakeZpkx(t, `
if [ -n "$ZPKX_SEEDED" ]; then echo nested >&2; exit 9; fi
[ "$1" = "--seed-from" ] && [ "$2" = "oci://seed" ] && [ "$3" = "--seed-ledger" ] || exit 8
[ "$CLICOLOR_FORCE" = "1" ] || exit 7
printf '{"project":"p%s","version":"1.0.0","digest":"sha256:d%s","signers":[],"keys":[],"source":"s"}\n' "$#" "$#" >> "$4"
echo "X=$5"
`)
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	base := []artifact.SeedEntry{{Project: "base", Version: "1", Digest: "sha256:b"}}
	p, err := newSeedProvisioner(z, "oci://seed", base)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	env, err := p.Provision([]string{"a@1", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(env) != "X=+a@1" {
		t.Fatalf("env = %q", env)
	}
	if _, err := p.Provision([]string{"c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision([]string{"c"}); err != nil { // same digest: deduped
		t.Fatal(err)
	}
	if got := len(p.Entries()); got != 3 {
		t.Fatalf("entries = %d, want 3 (base + two closures): %+v", got, p.Entries())
	}
	if env, err := p.Provision(nil); err != nil || env != "" {
		t.Fatalf("empty closure = %q, %v", env, err)
	}
	if p.calls != 3 {
		t.Fatalf("an empty closure must not start zpkx: calls = %d", p.calls)
	}
}

func TestProvisionerRefusals(t *testing.T) {
	if _, err := newSeedProvisioner("zpkx", "", nil); err == nil {
		t.Fatal("no seed registry must be refused")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if _, err := newSeedProvisioner("zpkx", "oci://seed", nil); err == nil {
		t.Fatal("no scratch directory must be refused")
	}
	t.Setenv("TMPDIR", t.TempDir())
	for name, body := range map[string]string{
		"exit":       "exit 3\n",
		"bad ledger": "echo notjson > \"$4\"\n",
	} {
		p, err := newSeedProvisioner(fakeZpkx(t, body), "oci://seed", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Provision([]string{"a"}); err == nil {
			t.Errorf("%s: must fail", name)
		}
		p.Close()
	}
	// No ledger written is no new entries, not an error.
	p, _ := newSeedProvisioner(fakeZpkx(t, "echo ok\n"), "oci://seed", nil)
	defer p.Close()
	if env, err := p.Provision([]string{"a"}); err != nil || strings.TrimSpace(env) != "ok" {
		t.Fatalf("%q %v", env, err)
	}
	// An environment past the bound is refused.
	big := fakeZpkx(t, "head -c 5000000 /dev/zero\n")
	p2, _ := newSeedProvisioner(big, "oci://seed", nil)
	defer p2.Close()
	if _, err := p2.Provision([]string{"a"}); err == nil {
		t.Fatal("a 5 MB environment must be refused")
	}
}

// A factory that cannot make its provisioning scratch directory stops before it
// builds anything, and says so.
func TestTheSeededFactoryStopsWithoutAScratchDirectoryForItsProvisioner(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://ghcr.io/go-pkgx/packages")
	r := newStageRig(t)
	args := append([]string{"--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist}, ledgerFlags(t, testSeedEntries)...)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if code := r.h.run(t, args...); code != 1 || !strings.Contains(r.h.errb.String(), "factory:") {
		t.Errorf("code=%d err=%q", code, r.h.errb.String())
	}
}

func TestEnvWithoutAndLimitWriter(t *testing.T) {
	got := envWithout([]string{"A=1", "AB=2", "A=3", "B=4"}, "A")
	if len(got) != 2 || got[0] != "AB=2" || got[1] != "B=4" {
		t.Fatalf("envWithout = %v", got)
	}
	var sb strings.Builder
	lw := &limitWriter{w: &sb, n: 4}
	if n, err := lw.Write([]byte("abcd")); n != 4 || err != nil {
		t.Fatalf("exact fit: %d %v", n, err)
	}
	if _, err := lw.Write([]byte("e")); err == nil {
		t.Fatal("past the bound must fail")
	}
}

func TestASeedRefusesAnyUpstreamDist(t *testing.T) {
	for _, up := range []string{"https://dist.pkgx.dev", "http://127.0.0.1:1", "oci://ghcr.io/go-pkgx/packages"} {
		if err := checkSeedUpstream(up); err == nil || !strings.Contains(err.Error(), "unsigned upstream") {
			t.Errorf("checkSeedUpstream(%q) = %v, want a refusal", up, err)
		}
	}
	for _, ok := range []string{"", "none"} {
		if err := checkSeedUpstream(ok); err != nil {
			t.Errorf("checkSeedUpstream(%q) = %v", ok, err)
		}
	}
	old := artifact.UpstreamDist
	artifact.UpstreamDist = "https://dist.pkgx.dev"
	defer func() { artifact.UpstreamDist = old }()
	p, err := newSeedProvisioner(fakeZpkx(t, "exit 0\n"), artifact.SeedRegistry, nil)
	if err == nil {
		p.Close()
		t.Fatal("a provisioner was made with dist.pkgx.dev as the upstream")
	}
}

func TestPlanVersionsResolveFromThePinnedSeedRegistryOnly(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	old := artifact.UpstreamDist
	artifact.UpstreamDist = ""
	defer func() { artifact.UpstreamDist = old }()
	p, err := newSeedProvisioner(fakeZpkx(t, "exit 0\n"), artifact.SeedRegistry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before := artifact.DistBase
	var during string
	v, err := p.Pick(func(project, constraint string) (string, error) {
		during = artifact.DistBase
		return "1.2.3", nil
	})("zlib.net", "*")
	if err != nil || v != "1.2.3" {
		t.Fatalf("Pick = %q %v", v, err)
	}
	if during != artifact.SeedRegistry {
		t.Errorf("resolved against %q, want the seed registry %q", during, artifact.SeedRegistry)
	}
	if artifact.DistBase != before {
		t.Errorf("DistBase not restored: %q", artifact.DistBase)
	}
	// A resolver error is passed through.
	if _, err := p.Pick(func(string, string) (string, error) { return "x", os.ErrNotExist })("a", "*"); err == nil {
		t.Error("a resolver error was swallowed")
	}
	// A registry that is not the pinned one is refused before anything resolves.
	q, _ := newSeedProvisioner(fakeZpkx(t, "exit 0\n"), "oci://other.example/packages", nil)
	defer q.Close()
	called := false
	if _, err := q.Pick(func(string, string) (string, error) { called = true; return "1", nil })("a", "*"); err == nil || called {
		t.Errorf("a non-pinned seed registry resolved (err=%v, called=%v)", err, called)
	}
}
