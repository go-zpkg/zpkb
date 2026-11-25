//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
