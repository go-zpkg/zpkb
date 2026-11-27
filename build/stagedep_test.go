package build

import (
	"os"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// ⛔⛔ A DEPENDENCY BUILT EARLIER IN THE SAME RUN MUST BE FOUND BY ITS OWN HASH.
//
// Seed pass 1c: gmp 6.3.0 was built (stage-only: installed, not published) while
// the seed already held another gmp 6.3.0. Asking the store by (project,
// version) was then ambiguous and StorePrefix fell back to the composed
// `/zpkg/gnu.org/gmp/v6.3.0`, which does not exist: mpfr's configure died with
// `"/zpkg/gnu.org/gmp/v6.3.0" shall be a valid directory`, and the dependency
// never entered mpfr's environment. libidn2 -> libpsl and curl are the same shape.
func TestADependencyBuiltEarlierInTheRunIsFoundByItsHash(t *testing.T) {
	cases := []struct {
		name, dep, ver string
		dependents     []string
	}{
		{"gmp-mpfr", "gnu.org/gmp", "6.3.0", []string{"gnu.org/mpfr"}},
		{"libidn2-libpsl-curl", "gnu.org/libidn2", "2.3.8", []string{"rockdaboot.github.io/libpsl", "curl.se"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tenv(t)
			tgt := target.Target{Platform: "linux", Arch: "x86-64"}
			store := os.Getenv("ZPKG_DIR")

			// The seed's own build of the same version, installed and hashed.
			seed := artifact.StoreBuildPrefix(store, c.dep, artifact.Ver{Raw: c.ver}, "ssssssssssssssss")
			if err := os.MkdirAll(seed, 0o755); err != nil {
				t.Fatal(err)
			}

			r := okRunner(c.dep, tgt)
			r.PickVersion = func(string, string) (string, error) { return c.ver, nil }
			r.ResolveVersion = func(any, string) (string, string, error) { return c.ver, "v" + c.ver, nil }
			r.ResolveDep = func(string, string) (string, error) { return c.ver, nil }

			bare := &pantry.Recipe{
				Distributable: map[string]any{"url": "https://x/v{{version.raw}}.tar.gz", "strip-components": 1},
				Build:         map[string]any{"script": []any{"make install"}},
			}
			dep, err := r.Build(bare, c.dep, "*", tgt, tgt, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dep.Install); err != nil {
				t.Fatalf("the staged dependency is not on disk: %v", err)
			}
			if dep.Install == seed {
				t.Fatal("the build landed on the seed's prefix")
			}

			for _, user := range c.dependents {
				recipe := &pantry.Recipe{
					Distributable: bare.Distributable,
					Dependencies:  map[string]any{c.dep: "*"},
					Build:         bare.Build,
				}
				// Only the dependency resolves to c.ver; the dependent is built at 1.0.0.
				r.ResolveVersion = func(any, string) (string, string, error) { return "1.0.0", "v1.0.0", nil }
				p, err := r.Plan(recipe, user, "*", tgt)
				if err != nil {
					t.Fatalf("%s: %v", user, err)
				}
				if len(p.BuildEnv) != 1 || p.BuildEnv[0].Path != dep.Install {
					t.Fatalf("%s: dependency prefix = %+v, want %s", user, p.BuildEnv, dep.Install)
				}
				if _, err := os.Stat(p.BuildEnv[0].Path); err != nil {
					t.Errorf("%s: the prefix it was handed does not exist: %v", user, err)
				}
			}
		})
	}
}

// Several builds installed and none built by this run: a refusal naming the
// ambiguity, never the composed path that does not exist.
func TestAmbiguousInstalledDependencyIsRefusedNotComposed(t *testing.T) {
	store := t.TempDir()
	v := artifact.Ver{Raw: "6.3.0"}
	for _, h := range []string{"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"} {
		if err := os.MkdirAll(artifact.StoreBuildPrefix(store, "gnu.org/gmp", v, h), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := DepTokens(map[string]any{"gnu.org/gmp": "*"}, nil, target.Target{Platform: "linux", Arch: "x86-64"}, store,
		func(string, string) (string, error) { return "6.3.0", nil }, "")
	if err == nil || !strings.Contains(err.Error(), "gnu.org/gmp") {
		t.Fatalf("want a refusal naming gnu.org/gmp, got %v", err)
	}
}

// Nothing installed: a dry run keeps the composed path, explicitly.
func TestDryRunKeepsTheComposedPathWhenNothingIsInstalled(t *testing.T) {
	store := t.TempDir()
	_, deps, err := DepTokens(map[string]any{"gnu.org/gmp": "*"}, nil, target.Target{Platform: "linux", Arch: "x86-64"}, store,
		func(string, string) (string, error) { return "6.3.0", nil }, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := artifact.StorePrefix(store, "gnu.org/gmp", artifact.Ver{Raw: "6.3.0"}); deps[0].Path != want {
		t.Errorf("path = %q, want %q", deps[0].Path, want)
	}
}
