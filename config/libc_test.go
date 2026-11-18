package config

import (
	"path/filepath"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// ⛔⛔ TWO LIBCS MUST NOT SHARE A BUILD TREE. Home/Src/Build/Test are where a
// build unpacks, compiles and tests; a second build inheriting the first's
// object files produces a WRONG artifact from a GREEN run, which is the worst
// shape a defect takes here — nothing fails, and the bottle is mixed.
//
// The separator stays "+" because this is a directory name rather than a path,
// so the component is target.OSDir() and not the slug.
func TestTheBuildTreeSeparatesByLibc(t *testing.T) {
	t.Setenv("ZPKG_RECIPE_DIR", "")
	t.Setenv("ZPKG_RECIPES_PATH", "")
	t.Setenv("ZPKG_DIR", "/opt/pkgx")
	t.Setenv("XDG_DATA_HOME", "/data")

	home := func(libc string) string {
		return Compute("acme.org/tool", "1.2.3", "abcdefghijklmnop",
			target.Target{Platform: "linux", Arch: "x86-64", Libc: libc}).Home
	}

	if got, want := home("musl"), filepath.FromSlash("/data/zpkb/linux-musl+x86-64/acme.org/tool/v1.2.3"); got != want {
		t.Errorf("Home = %q, want %q", got, want)
	}
	if got, want := home("gnu"), filepath.FromSlash("/data/zpkb/linux-gnu+x86-64/acme.org/tool/v1.2.3"); got != want {
		t.Errorf("Home = %q, want %q", got, want)
	}

	// ⭐ THE CONTROL: an unnamed libc keeps the directory every existing build
	// tree on every machine already uses. A component appended unconditionally
	// would orphan all of them — not a correctness defect, but a silent
	// re-download and rebuild of everything, which is the kind of cost that
	// gets blamed on the network.
	if got, want := home(""), filepath.FromSlash("/data/zpkb/linux+x86-64/acme.org/tool/v1.2.3"); got != want {
		t.Errorf("Home = %q, want %q — an existing build tree was orphaned", got, want)
	}
}
