//go:build !windows

package main

import (
	"encoding/json"
	"errors"
	"io"
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

var testEntry = artifact.SeedEntry{Project: "p", Version: "1.0.0", Digest: "sha256:d", Signers: []string{}, Keys: []string{}, Source: "s"}

// seedStore points the artifact store at a directory of the test's own, which
// the fake zpkx stages seeds in (the real one installs them there).
func seedStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ZPKG_DIR", dir)
	return dir
}

// stageSh is the shell text that stages e the way the installer does: a prefix
// named from the digest, carrying the marker with the digest in it.
func stageSh(dir string, e artifact.SeedEntry) string {
	return stageAs(dir, e, e.Digest)
}

func stageAs(dir string, e artifact.SeedEntry, markDigest string) string {
	prefix := seedPrefixOf(dir, e)
	return "mkdir -p '" + prefix + "' && printf '%s\\n' '" + markDigest + "' > '" + prefix + "/" + artifact.SeedMarkerName + "'\n"
}

// emitSh is the shell text that writes e's record to the ledger descriptor.
func emitSh(e artifact.SeedEntry) string {
	b, _ := json.Marshal(e)
	return "printf '%s\\n' '" + string(b) + "' >&3\n"
}

// The window between zpkx's write and the read-back: a process of the same user
// that tries to edit the ledger in it finds no file to edit (the ledger is a
// pipe, there is nothing in the factory's directory).
func TestProvisionerLedgerHasNoFileToEdit(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	var p *seedProvisioner
	dirOf := filepath.Join(t.TempDir(), "dir")
	z := fakeZpkx(t, stageSh(seedStore(t), testEntry)+emitSh(testEntry)+
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
		t.Errorf("the entry was lost: %+v", es)
	}
}

// A descendant that keeps the pipe open after the call ended does not hang the
// factory, and the read the deadline ended is REFUSED: what it got is not known
// to be the whole ledger, even when it looks complete.
func TestProvisionerRefusesAReadTheDeadlineEnded(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	z := fakeZpkx(t, stageSh(seedStore(t), testEntry)+emitSh(testEntry)+"(sleep 3 >/dev/null 2>&1 &)\n")
	p, err := newSeedProvisioner(z, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := time.Now()
	if _, err := p.Provision([]string{"a"}); !errors.Is(err, errLedgerNotClosed) {
		t.Fatalf("a deadline-ended read was accepted: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the read waited for a descendant that held the pipe")
	}
	if len(p.Entries()) != 0 {
		t.Errorf("entries = %+v", p.Entries())
	}
}

// The ledger is the descriptor, never a path: no argument names one, so a build
// root with no /dev/fd, or one a recipe made, changes nothing. A zpkx that still
// opened the ledger by the argument it was given would write a regular file and
// leave the pipe empty, and the seeds it staged would be unaccounted for.
func TestProvisionerPassesADescriptorAndRefusesAPathWritingZpkx(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	dir := seedStore(t)
	check := "for a in \"$@\"; do case \"$a\" in */dev/fd*|/*) exit 6;; esac; done\n" +
		"[ \"$3\" = \"--seed-ledger-fd\" ] && [ \"$4\" = \"3\" ] || exit 7\n"
	good := fakeZpkx(t, check+stageSh(dir, testEntry)+emitSh(testEntry))
	p, err := newSeedProvisioner(good, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Provision([]string{"a"}); err != nil {
		t.Fatalf("the descriptor form: %v", err)
	}
	t.Chdir(t.TempDir())
	b, _ := json.Marshal(artifact.SeedEntry{Project: "q", Version: "1", Digest: "sha256:q", Signers: []string{}, Keys: []string{}, Source: "s"})
	old := fakeZpkx(t, stageSh(dir, artifact.SeedEntry{Project: "q", Version: "1", Digest: "sha256:q"})+
		"printf '%s\\n' '"+string(b)+"' >> \"$4\"\n")
	q, err := newSeedProvisioner(old, "oci://seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err := q.Provision([]string{"a"}); err == nil || !strings.Contains(err.Error(), "lost an entry") {
		t.Fatalf("an empty ledger beside a staged seed was accepted: %v", err)
	}
}

// The ledger is checked against what the call staged: an injected record, a
// record whose prefix carries another digest, a marker that is not a file, and a
// staged seed with no record (removed, or never written) are all refused; the
// staged, recorded one is accepted.
func TestProvisionerCrossChecksTheLedgerAgainstTheStagedSeeds(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	other := artifact.SeedEntry{Project: "gnu.org/o", Version: "2.0", Digest: "sha256:e", Signers: []string{}, Keys: []string{}, Source: "s"}
	deep := artifact.SeedEntry{Project: "a.org/b/c", Version: "3", Digest: "sha256:f", Signers: []string{}, Keys: []string{}, Source: "s"}
	for name, c := range map[string]struct {
		script func(dir string) string
		want   string // "" accepts
	}{
		"matching":            {func(d string) string { return stageSh(d, testEntry) + emitSh(testEntry) }, ""},
		"three-level project": {func(d string) string { return stageSh(d, deep) + emitSh(deep) }, ""},
		"injected":            {func(d string) string { return emitSh(testEntry) }, "did not stage"},
		"another digest in the marker": {func(d string) string {
			return stageAs(d, testEntry, "sha256:other") + emitSh(testEntry)
		}, "did not stage"},
		"marker is a symlink": {func(d string) string {
			p := seedPrefixOf(d, testEntry)
			return "mkdir -p '" + p + "' && ln -s /etc/hosts '" + p + "/" + artifact.SeedMarkerName + "'\n" + emitSh(testEntry)
		}, "did not stage"},
		"removed": {func(d string) string {
			return stageSh(d, testEntry) + stageSh(d, other) + emitSh(testEntry)
		}, "lost an entry"},
		"nothing written": {func(d string) string { return stageSh(d, testEntry) }, "lost an entry"},
	} {
		dir := seedStore(t)
		p, err := newSeedProvisioner(fakeZpkx(t, c.script(dir)), "oci://seed", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Provision([]string{"a"})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
		if c.want != "" && len(p.Entries()) != 0 {
			t.Errorf("%s: a refused ledger was recorded: %+v", name, p.Entries())
		}
		p.Close()
	}
}

func TestTheSeedPipeProbe(t *testing.T) {
	if err := seedPipeSupported(); err != nil {
		t.Fatalf("this system's pipes: %v", err)
	}
	// Each failure is given on its own, with the other end able to succeed, so
	// no refusal is held by another one.
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := probePipe(func() (io.ReadCloser, io.WriteCloser, error) { return r, w, errors.New("no pipes") }); err == nil {
		t.Error("a system that cannot make a pipe passed")
	}
	good := func() io.ReadCloser { return io.NopCloser(strings.NewReader("x")) }
	if err := probePipe(func() (io.ReadCloser, io.WriteCloser, error) { return good(), nopWriter{failingWriter{}}, nil }); err == nil {
		t.Error("a pipe that cannot be written passed")
	}
	if err := probePipe(func() (io.ReadCloser, io.WriteCloser, error) {
		return io.NopCloser(strings.NewReader("")), nopWriter{io.Discard}, nil
	}); err == nil {
		t.Error("a pipe that cannot be read passed")
	}
	if err := probePipe(func() (io.ReadCloser, io.WriteCloser, error) { return good(), nopWriter{io.Discard}, nil }); err != nil {
		t.Errorf("a working pipe was refused: %v", err)
	}
}

type nopWriter struct{ io.Writer }

func (nopWriter) Close() error { return nil }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

// A call that writes more than a ledger may hold is refused, and is not left
// blocked on a full pipe.
func TestProvisionerRefusesAnOversizedLedger(t *testing.T) {
	t.Setenv("ZPKX_SEEDED", "oci://seed")
	z := fakeZpkx(t, "head -c 17000000 /dev/zero | tr '\\0' 'x' >&3\n")
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
	if b, err := drainLedger(r); !errors.Is(err, errLedgerNotClosed) || len(b) != 0 {
		t.Errorf("a deadline is a read that did not finish, and is refused: %q, %v", b, err)
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
	// Arguments are --seed-from X --seed-ledger-fd 3 +spec...: $5 is the first
	// spec, and $# (5 for one spec, 6 for two) picks the seed this call stages.
	dir := seedStore(t)
	five := artifact.SeedEntry{Project: "p5", Version: "1.0.0", Digest: "sha256:d5", Signers: []string{}, Keys: []string{}, Source: "s"}
	six := artifact.SeedEntry{Project: "p6", Version: "1.0.0", Digest: "sha256:d6", Signers: []string{}, Keys: []string{}, Source: "s"}
	z := fakeZpkx(t, `
if [ -n "$ZPKX_SEEDED" ]; then echo nested >&2; exit 9; fi
[ "$1" = "--seed-from" ] && [ "$2" = "oci://seed" ] && [ "$3" = "--seed-ledger-fd" ] && [ "$4" = "3" ] || exit 8
[ "$CLICOLOR_FORCE" = "1" ] || exit 7
case "$#" in
5)
`+stageSh(dir, five)+emitSh(five)+`;;
6)
`+stageSh(dir, six)+emitSh(six)+`;;
esac
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
		"bad ledger": "echo notjson >&3\n",
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
