package main

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// minZpkxVersion is the oldest zpkx the seed provisioner can drive: it runs
//
//	zpkx --seed-from <registry> --seed-ledger-fd 3 +spec…
//
// (seedprovision.go), and --seed-ledger-fd first exists in zpkx v0.46.0. An
// older zpkx dies on every call with "--seed-from needs --seed-ledger", which
// names no version: go-zpkg/packages pinned zpkb v0.113.0 beside zpkx v0.45.0 and
// lost an hour of seed pass 1d to it.
//
// It is the zpkx tag zpkb's own CI real-zpkx lane installs
// (.github/workflows/ci.yml), the one this code is TESTED against, and
// TestMinZpkxVersionIsTheTagCIInstalls keeps the two equal: raise both together.
const minZpkxVersion = "0.46.1"

// allowUnversionedZpkxEnv is the explicit opt-in for a zpkx whose version
// cannot be established. It is announced on stderr when used.
const allowUnversionedZpkxEnv = "ZPKB_ALLOW_UNVERSIONED_ZPKX"

// readZpkxModuleVersion is a seam: the factory tests that stage a seeded plan
// run no zpkx at all.
var readZpkxModuleVersion = moduleVersionOf

// queryZpkxVersion is the second seam: `zpkx --version`.
var queryZpkxVersion = zpkxVersionOf

// moduleVersionOf reads the main module's version out of the Go binary itself:
// "v0.45.0" for `go install …@v0.45.0`, "(devel)" for a build from a checkout.
// ⛔ NOT from `zpkx --version`: that is a variable zpkx stamps only through
// -ldflags and defaults to "dev", so a `go install …@v0.45.0` — how the
// go-zpkg/packages workflows install it — prints "dev" too.
func moduleVersionOf(bin string) (string, error) {
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		return "", err
	}
	return bi.Main.Version, nil
}

// zpkxVersionOf runs `zpkx --version`, which prints "zpkx <version>": the
// release tag without its "v" when stamped by -ldflags, "dev" otherwise.
func zpkxVersionOf(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("could not run `%s --version`: %w", bin, err)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[0] != "zpkx" {
		return "", fmt.Errorf("`%s --version` printed %q, not \"zpkx <version>\"", bin, strings.TrimSpace(string(out)))
	}
	return f[1], nil
}

// parseSemver reads major.minor.patch, with an optional leading "v" and an
// ignored -pre/+build suffix.
func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	var v [3]int
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil { // a sign cannot reach here: "-" and "+" were cut above
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// olderThanMin reports whether a parsed version is below minZpkxVersion.
func olderThanMin(have [3]int) bool {
	want, _ := parseSemver(minZpkxVersion)
	for i := range have {
		if have[i] != want[i] {
			return have[i] < want[i]
		}
	}
	return false
}

// requireZpkx refuses a zpkx older than minZpkxVersion, naming both versions.
//
// The version is the one in the binary's build info. A binary that carries none
// ("(devel)", or one that is not a Go binary) falls back to what it stamps into
// `--version`: a release build stamps its tag there, and a number is a number. A
// version that is still not a semver is REFUSED, because a gate that cannot read
// the answer must not read it as "fine"; $ZPKB_ALLOW_UNVERSIONED_ZPKX=1 is the
// explicit opt-in, and it says so.
func requireZpkx(bin string, stderr io.Writer) error {
	src, got := "its build info", ""
	mod, merr := readZpkxModuleVersion(bin)
	if merr == nil {
		got = mod
	}
	if have, ok := parseSemver(got); ok && strings.HasPrefix(got, "v") {
		return tooOld(bin, src, got, have)
	}
	// "(devel)", empty, or unreadable: ask the binary what it stamped.
	stamped, serr := queryZpkxVersion(bin)
	if serr == nil {
		if have, ok := parseSemver(stamped); ok {
			return tooOld(bin, "`--version`", stamped, have)
		}
	}
	if os.Getenv(allowUnversionedZpkxEnv) == "1" {
		fmt.Fprintf(stderr, "factory: WARNING: %s reports no zpkx version (build info %q, --version %q); accepted because %s=1; it must be zpkx v%s or newer\n",
			bin, got, stamped, allowUnversionedZpkxEnv, minZpkxVersion)
		return nil
	}
	return fmt.Errorf("a seeded run needs zpkx v%s or newer and cannot tell which %s is (build info: %q / %v; --version: %q / %v); install a released zpkx, or set %s=1 to accept it unchecked",
		minZpkxVersion, bin, got, merr, stamped, serr, allowUnversionedZpkxEnv)
}

func tooOld(bin, src, got string, have [3]int) error {
	if olderThanMin(have) {
		return fmt.Errorf("zpkx %s is too old: zpkb drives `zpkx --seed-from … --seed-ledger-fd`, which needs zpkx v%s or newer (%s reports %s in %s) — install a newer zpkx", bin, minZpkxVersion, bin, got, src)
	}
	return nil
}
