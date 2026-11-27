//go:build !windows

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The seed build, end to end, with NO stand-in for either program: the real
// zpkx (the release the packages repository pins, handed in as
// $ZPKB_E2E_ZPKX) installs the seeded toolchain from the real seed registry
// and writes the ledger, the real zpkb is built from this tree and runs the
// factory under that seed, and a recipe is built from a local source.
//
// Every other test of the seed path stubs one of the two programs, which is
// how a factory whose recipes could not get their dependencies passed all of
// them: zpkx refuses every package request under a seed, and nothing that
// called a stand-in could tell. This one needs the network (the seed registry)
// and is off unless $ZPKB_E2E_ZPKX names the binary, so the ordinary suite
// stays offline; CI sets it.
const (
	e2eSeedRegistry = "oci://ghcr.io/go-pkgx/packages"
	e2eProject      = "example.org/seedtiny"
	e2eNested       = "example.org/nested"
)

func e2eTarball(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	body := []byte("tiny\n")
	if err := tw.WriteHeader(&tar.Header{Name: "seedtiny-1.0.0/README", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func e2eRecipe(t *testing.T, pantry, proj, url, script string) {
	t.Helper()
	dir := filepath.Join(pantry, "projects", filepath.FromSlash(proj))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "distributable:\n  url: " + url + "\nversions:\n  - 1.0.0\ndependencies:\n  zlib.net: '*'\nbuild:\n  script:\n    - " + script + "\ntest: 'true'\n"
	if err := os.WriteFile(filepath.Join(dir, "package.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func e2eRun(t *testing.T, env []string, name string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// The command the real zpkx runs under a seed is the build. The ledger's write
// end is descriptor 3 of zpkx and must not be one of the build's: a build that
// could write to it could add an entry no install made. The command here tries,
// from its own shell and from a child of it, and both must fail; the ledger the
// reader gets holds what zpkx installed and nothing else.
func TestTheBuildCommandCannotWriteTheRealZpkxsLedger(t *testing.T) {
	zpkx := os.Getenv("ZPKB_E2E_ZPKX")
	if zpkx == "" {
		t.Skip("ZPKB_E2E_ZPKX names the real zpkx binary; unset, so the network-free suite skips this")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	cmd := exec.Command(zpkx, "--seed-from", e2eSeedRegistry, "--seed-ledger-fd", "3", "+zlib.net", "--",
		"/bin/sh", "-c", `if echo forged-by-the-build >&3 2>/dev/null; then exit 7; fi; if (echo forged-by-a-child >&3) 2>/dev/null; then exit 8; fi`)
	store := t.TempDir()
	cmd.Env = append(os.Environ(), "ZPKG_DIR="+store, "ZPKG_DIST=", "ZPKX_SEEDED=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.ExtraFiles = []*os.File{pw}
	got := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(pr); got <- b }()
	runErr := cmd.Run()
	pw.Close()
	ledger := <-got
	if runErr != nil {
		t.Fatalf("zpkx with a build that tries the ledger: %v (7 = the build wrote it, 8 = a child did)\n%s", runErr, out.String())
	}
	if len(ledger) == 0 || !strings.Contains(string(ledger), "zlib.net") {
		t.Errorf("the ledger zpkx wrote does not record the install: %q", ledger)
	}
	if strings.Contains(string(ledger), "forged") {
		t.Errorf("the build wrote into the ledger:\n%s", ledger)
	}
}

func TestSeedBuildEndToEndWithTheRealZpkxAndZpkb(t *testing.T) {
	zpkx := os.Getenv("ZPKB_E2E_ZPKX")
	if zpkx == "" {
		t.Skip("ZPKB_E2E_ZPKX names the real zpkx binary; unset, so the network-free suite skips this")
	}
	work := t.TempDir()
	zpkb := filepath.Join(work, "zpkb")
	if out, err := exec.Command("go", "build", "-o", zpkb, ".").CombinedOutput(); err != nil {
		t.Fatalf("building the real zpkb: %v\n%s", err, out)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(e2eTarball(t))
	}))
	defer srv.Close()
	pantry := filepath.Join(work, "pantry")
	url := srv.URL + "/seedtiny-{{version}}.tar.gz"
	e2eRecipe(t, pantry, e2eProject, url,
		`mkdir -p "{{prefix}}/bin" && printf '#!/bin/sh\necho ok\n' > "{{prefix}}/bin/seedtiny" && chmod +x "{{prefix}}/bin/seedtiny"`)
	// A recipe that asks zpkx for a package of its own, from inside the build.
	// Under a seed that must be refused, and it must not take the first down.
	e2eRecipe(t, pantry, e2eNested, url, zpkx+` +gnu.org/make -- true`)

	store := filepath.Join(work, "store")
	ledger := filepath.Join(work, "seed-ledger.jsonl")
	base := append(os.Environ(), "ZPKG_DIR="+store, "ZPKG_DIST=", "ZPKX_SEEDED=")

	// The outside of the build: the real zpkx brings the seeded toolchain in
	// and records what it installed.
	if _, stderr, err := e2eRun(t, base, zpkx, "--seed-from", e2eSeedRegistry, "--seed-ledger", ledger, "+zlib.net"); err != nil {
		t.Fatalf("zpkx seed install: %v\n%s", err, stderr)
	}
	digest, stderr, err := e2eRun(t, base, zpkx, "--seed-digest", ledger)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(digest), "sha256:") {
		t.Fatalf("zpkx --seed-digest = %q, %v\n%s", digest, err, stderr)
	}
	digest = strings.TrimSpace(digest)

	// The inside: the factory runs under the seed zpkx marks for what it runs.
	artifacts := filepath.Join(work, "dist")
	// The plan resolves dependencies through the upstream the distribution does
	// not carry, as the real factory does while the rebuild is in flight.
	inside := append(os.Environ(), "ZPKG_DIR="+store, "ZPKX_SEEDED="+e2eSeedRegistry)
	stdout, stderr, runErr := e2eRun(t, inside, zpkb, "factory",
		"--stage-only", "--platform", runtime.GOOS+"/"+map[string]string{"amd64": "x86-64", "arm64": "aarch64"}[runtime.GOARCH],
		"--recipe-dir", pantry, "--recipes", e2eProject+" "+e2eNested, "--max-versions", "1",
		"--to", "oci://127.0.0.1:1/none", "--artifacts", artifacts, "--zpkx", zpkx,
		"--seed-ledger", ledger, "--seed-ledger-sha256", digest,
		"--failures", filepath.Join(work, "failures.txt"), "--failures-detail", filepath.Join(work, "failures-detail.txt"),
		"--tests", filepath.Join(work, "tests.txt"), "--test=false")
	if runErr != nil {
		t.Fatalf("the seeded factory failed: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout, stderr)
	}

	// The recipe that needed only its seeded dependency was built and staged,
	// and the plan carries the seed it was built from.
	plan, err := os.ReadFile(filepath.Join(artifacts, stagePlanName))
	if err != nil {
		t.Fatalf("no stage plan: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	detail, _ := os.ReadFile(filepath.Join(work, "failures-detail.txt"))
	t.Logf("factory stdout:\n%s\nstderr:\n%s\nfailures:\n%s", stdout, stderr, detail)
	for _, want := range []string{e2eProject, "zlib.net"} {
		if !strings.Contains(string(plan), want) {
			t.Errorf("the stage plan does not mention %q:\n%s", want, plan)
		}
	}
	// The factory provisioned the closures of its recipes through the real zpkx
	// into ledgers of its own and merged them into what the plan signs, so the
	// digest the plan carries covers more than the one the outside recorded.
	var parsed struct {
		Seed struct {
			Digest  string            `json:"digest"`
			Entries []json.RawMessage `json:"entries"`
		} `json:"seed"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		t.Fatalf("the stage plan is not JSON: %v", err)
	}
	if len(parsed.Seed.Digest) != 64 || parsed.Seed.Digest == strings.TrimPrefix(digest, "sha256:") || len(parsed.Seed.Entries) == 0 {
		t.Errorf("the plan's seed = %d entries, digest %q; want the provisioned set, not the outside's %q", len(parsed.Seed.Entries), parsed.Seed.Digest, digest)
	}
	// The one that asked zpkx for a package from inside its build was refused.
	if strings.Contains(string(plan), e2eNested) {
		t.Errorf("a recipe that installed a package under a seed was staged:\n%s", plan)
	}
	if !strings.Contains(string(detail), e2eNested) || !strings.Contains(string(detail), "a seed is in force") {
		t.Errorf("the nested package request is not among the failures, refused for the seed:\n%s", detail)
	}
}
