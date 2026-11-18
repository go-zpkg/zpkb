package build

import (
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/target"
)

// ⛔⛔ THREE DIFFERENT ABIs MUST NOT SHARE ONE IDENTITY.
//
// MEASURED on 2026-11-18, before the fix, by this same test: the container's
// system glibc, the gnu.org/glibc artifact, and that artifact pinned to
// 2.27.0 all produced `v1.2.3-hhhrjzyh2dk56y7tc`. `--libc` and `--glibc` are
// per-run flags that append `"+gnu.org/glibc@<v>"` to the generated script's
// environment eval, so they never pass through recipe.Dependencies and never
// reached the identity.
//
// That is go-zpkg/packages#225's own sentence — "promote the glibc input into
// a recorded property" — as a live defect, and it needed no musl to exist: the
// factory passes these flags today.
func TestTheLibcChoiceReachesTheBuildIdentity(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}

	build := func(mode, glibc string) string {
		t.Helper()
		tenv(t)
		r := okRunner("acme.org/tool", tgt)
		r.LibcMode, r.Glibc = mode, glibc
		res, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, "")
		if err != nil {
			t.Fatalf("build(%q,%q): %v", mode, glibc, err)
		}
		return prefixName(res.Install)
	}

	sys := build("", "")
	zpkx := build("zpkx", "")
	pin := build("zpkx", "2.27.0")

	if sys == zpkx {
		t.Errorf("the system libc and the gnu.org/glibc artifact share one identity (%s)", sys)
	}
	if zpkx == pin {
		t.Errorf("glibc newest and glibc 2.27.0 share one identity (%s)", zpkx)
	}
	if sys == pin {
		t.Errorf("the system libc and a pinned artifact glibc share one identity (%s)", sys)
	}
}

// ⭐ THE CONTROL, AND IT IS WHAT BOUNDS THE BLAST RADIUS: an ordinary build —
// no --libc, which is every darwin, windows and wasip1 build and every linux
// build that does not ask for the sovereign libc — keeps exactly the identity
// it had. Only builds that PASSED the flag get a new hash, and those are the
// ones that were wrong.
func TestAnOrdinaryBuildsIdentityIsUnchanged(t *testing.T) {
	for _, tgt := range []target.Target{
		{Platform: "linux", Arch: "x86-64"},
		{Platform: "darwin", Arch: "aarch64"},
	} {
		plain, err := concreteOf(idRecipe(), tgt, nil, libcChoice{})
		if err != nil {
			t.Fatal(err)
		}
		if len(plain.Deps) != 0 {
			t.Errorf("%s: a build that asked for no libc gained %d dep(s): %+v",
				tgt.Slug(), len(plain.Deps), plain.Deps)
		}
	}
}

// ⛔ AND NOT ON A PLATFORM THAT NEVER GETS THE INJECTION. wrapper.go adds the
// glibc only under `LibcZpkx && Platform == "linux"`, so recording it for a
// darwin build would make the identity claim a link that never happened —
// a false entry in the one record a consumer is meant to trust.
func TestTheLibcIsNotRecordedWhereItIsNotInjected(t *testing.T) {
	for _, tgt := range []target.Target{
		{Platform: "darwin", Arch: "aarch64"},
		{Platform: "windows", Arch: "x86-64"},
		{Platform: "wasip1", Arch: "wasm"},
	} {
		c, err := concreteOf(idRecipe(), tgt, nil, libcChoice{Mode: "zpkx", Version: "2.27.0"})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range c.Deps {
			if d.Project == "gnu.org/glibc" {
				t.Errorf("%s records a glibc it never linked against", tgt.Slug())
			}
		}
	}
}

// The recorded entry says what it is: the project, and the pin when there was
// one. ⚠ An EMPTY version is the stated limit — "newest at eval time" is not
// knowable before the compiler runs, and the identity must be.
func TestTheRecordedLibcNamesTheProjectAndThePin(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	for _, tc := range []struct{ pin, want string }{{"2.27.0", "2.27.0"}, {"", ""}} {
		c, err := concreteOf(idRecipe(), tgt, nil, libcChoice{Mode: "zpkx", Version: tc.pin})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Deps) != 1 || c.Deps[0].Project != "gnu.org/glibc" || c.Deps[0].Version != tc.want {
			t.Errorf("pin %q → %+v", tc.pin, c.Deps)
		}
		if c.Deps[0].Hash != "" {
			t.Errorf("pin %q recorded a hash (%q); nothing resolved this edge to a prefix",
				tc.pin, c.Deps[0].Hash)
		}
	}
}

// ⛔⛔ A musl TARGET MUST NOT RECORD A GLIBC DEPENDENCY, and until this test
// existed it did. go-zpkg/zpkb#502 made `linux-musl/x86-64` expressible and
// go-zpkg/zpkb#504 put the libc in the identity — by writing the literal
// "gnu.org/glibc". The two were correct apart and wrong together: the bottle
// would carry a manifest naming glibc, `artifact.VerifySpec` would recompute
// the hash from that same manifest, and it would VERIFY. A record that is
// wrong and self-consistent is worse than one that is missing.
func TestAMuslTargetRecordsMuslAndNotGlibc(t *testing.T) {
	for _, tc := range []struct{ libc, want string }{
		{"musl", "musl.libc.org"},
		{"gnu", "gnu.org/glibc"},
		// The control: an unnamed libc is every build published so far, and the
		// sovereign mode it is paired with exists to target the glibc artifact.
		{"", "gnu.org/glibc"},
	} {
		tgt := target.Target{Platform: "linux", Arch: "x86-64", Libc: tc.libc}
		c, err := concreteOf(idRecipe(), tgt, nil, libcChoice{Mode: "zpkx"})
		if err != nil {
			t.Fatalf("libc %q: %v", tc.libc, err)
		}
		if len(c.Deps) != 1 || c.Deps[0].Project != tc.want {
			t.Errorf("libc %q → %+v, want one dep on %s", tc.libc, c.Deps, tc.want)
		}
	}
}

// ⭐ THE TWO DEFINITIONS OF THE GLIBC PROJECT STRING MUST AGREE, and nothing
// else can say so: `target` holds the libc→project table and `artifact` holds
// `GlibcProject`, in different modules, with no import between them. A silent
// divergence would send the identity's dependency and the loader search to two
// different project directories — judge and subject counting differently.
func TestTheTwoGlibcProjectStringsAgree(t *testing.T) {
	got, ok := target.LibcProject("gnu")
	if !ok {
		t.Fatal(`target.LibcProject("gnu") reports no project`)
	}
	if got != artifact.GlibcProject {
		t.Errorf("target says %q, artifact.GlibcProject says %q", got, artifact.GlibcProject)
	}
}

// ⚠ AN UNKNOWN LIBC IS AN ERROR, NOT A DROPPED FIELD. Returning "no dep" for a
// name with no project would put the build back in the state #504 ended —
// linking one libc and recording nothing — and it would do it silently, which
// is the worse half.
func TestAnUnnameableLibcRefusesRatherThanRecordingNothing(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64", Libc: "bionic"}
	_, err := concreteOf(idRecipe(), tgt, nil, libcChoice{Mode: "zpkx"})
	if err == nil {
		t.Fatal("a libc with no project was accepted, and the identity recorded nothing")
	}
	if !strings.Contains(err.Error(), "bionic") {
		t.Errorf("error = %v; want it to name the libc", err)
	}
}

func prefixName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
