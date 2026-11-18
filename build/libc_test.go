package build

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

var muslTarget = target.Target{Platform: "linux", Arch: "x86-64", Libc: "musl"}

// ⛔⛔ THE PUBLISHED IDENTITY MUST CARRY THE LIBC, and this is the site where
// omitting it is unrecoverable rather than merely inconvenient.
//
// artifact.VerifySpec recomputes the hash from the manifest a consumer can
// read, so whatever Concrete.Platform leaves out is something no consumer can
// check afterwards. Before this, a bottle built against musl and one built
// against glibc carried the SAME Platform, hashed alike, and the mixed closure
// that go-zpkg/packages#225 exists to prevent would have verified.
func TestTheBuildIdentityCarriesTheLibc(t *testing.T) {
	c, err := concreteOf(idRecipe(), muslTarget, nil, libcChoice{})
	if err != nil {
		t.Fatalf("concreteOf: %v", err)
	}
	if c.Platform != "linux-musl/x86-64" {
		t.Errorf("Concrete.Platform = %q, want linux-musl/x86-64", c.Platform)
	}

	// ⭐ AND THE TWO MUST NOT HASH ALIKE. Asserting the string alone would pass
	// on a Platform that reached the struct but not the hash.
	glibc := mustHash(t, idRecipe(), target.Target{Platform: "linux", Arch: "x86-64", Libc: "gnu"}, nil)
	musl := mustHash(t, idRecipe(), muslTarget, nil)
	if glibc == musl {
		t.Error("a glibc build and a musl build share one identity — a mixed closure would verify")
	}
}

// ⭐ THE CONTROL: an unnamed libc must produce exactly the identity published
// bottles already carry. A component appended unconditionally would change the
// hash of every artifact in existence, and artifact.VerifySpec would then read
// each of them as tampered with.
func TestAnUnnamedLibcLeavesTheIdentityAlone(t *testing.T) {
	c, err := concreteOf(idRecipe(), idTarget, nil, libcChoice{})
	if err != nil {
		t.Fatalf("concreteOf: %v", err)
	}
	if c.Platform != "linux/x86-64" {
		t.Errorf("Concrete.Platform = %q, want linux/x86-64 — a published identity moved", c.Platform)
	}
}

// The artifact lands under the libc too, or two bottles of the same project and
// version overwrite each other and the survivor says nothing about which it is.
//
// ⚠ The argument is captured from the RUNNER rather than asserted against a
// path this test composes: composing it would prove only that this test and
// target.OSDir agree, which they would even if runner.go still passed Platform.
func TestTheArtifactPathCarriesTheLibc(t *testing.T) {
	for _, tc := range []struct {
		name string
		tgt  target.Target
		want string
	}{
		{"named", muslTarget, "linux-musl"},
		// ⚠ The subtest name is one word on purpose: Go puts it in t.TempDir(),
		// and the prefix-map guard refuses a build root containing '=' ':' or
		// ',' — which a descriptive name here promptly produced.
		{"unnamed", idTarget, "linux"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenv(t)
			r := okRunner("acme.org/tool", tc.tgt)
			var gotOS, gotArch string
			r.WriteArtifact = func(_, _, _, osn, arch, out string) (string, error) {
				gotOS, gotArch = osn, arch
				return filepath.Join(out, "b.tar.gz"), nil
			}
			dist := filepath.Join(t.TempDir(), "dist")
			if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tc.tgt, tc.tgt, dist); err != nil {
				t.Fatalf("build: %v", err)
			}
			if gotOS != tc.want || gotArch != "x86-64" {
				t.Errorf("WriteArtifact got os=%q arch=%q, want %q and x86-64", gotOS, gotArch, tc.want)
			}
		})
	}
}

// ⛔ THE INSTALL PREFIX SEPARATES TOO, and it does so through the identity
// rather than through a path component: the prefix is `v<version>-h<hash>`,
// and the hash now covers the libc. Two libcs installing to one prefix would
// mean the second build silently replaced the first.
//
// This goes through the pipeline rather than composing a path, for the reason
// seedInstall's own comment gives: a composed path is one the build never uses.
func TestTheInstallPrefixSeparatesByLibc(t *testing.T) {
	tenv(t)
	glibc := seedInstall(t, "acme.org/tool", target.Target{Platform: "linux", Arch: "x86-64", Libc: "gnu"})
	musl := seedInstall(t, "acme.org/tool", muslTarget)
	if glibc == musl {
		t.Errorf("both libcs installed to %q", glibc)
	}
	if _, err := os.Stat(glibc); err != nil {
		t.Errorf("the glibc install is not there: %v", err)
	}
}
