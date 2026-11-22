package buildscript

import (
	"regexp"
	"sort"

	"github.com/go-zpkg/zpkb/target"
)

// exportedRE captures the NAME of every `export NAME=` the wrapper emits.
//
// It matches `export` ANYWHERE in a line rather than at its start, because the
// preamble guards some of them: wrapper.go emits
//
//	[ -n "$ZPKB_GLIBC_PREFIX" ] && export ZPKB_GLIBC_PREFIX="$ZPKB_GLIBC_PREFIX/"
//
// and a line-anchored pattern would miss it. A bare `NAME=value` is NOT matched
// on purpose: every variable this package publishes to a build is `export`ed,
// and widening the pattern would let any `--foo=bar` on a command line register
// as a name the builder provides — which is the direction that WEAKENS the gate
// built on this list, since an unknown name would then look known.
var exportedRE = regexp.MustCompile(`export[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)=`)

// ExportedNames returns every environment variable name this package puts into
// a build or test environment, in any mode, sorted and deduplicated.
//
// ⛔⛔ IT IS DERIVED BY RENDERING, NOT WRITTEN DOWN, and that is the whole
// point. go-zpkg/zpkb#494 exists because four recipes shipped reading a
// variable the builder does not export — `$ZBK_CC_FREESTANDING` after the
// prefix moved to `ZPKB_`, `$PKGX_DIR` after the store variable became
// `ZPKG_DIR`, `BREWKIT_TARGET` after `ZPKB_TARGET` — each found by a later
// sweep that believed it was the last. A hand-written list of valid names would
// be a FIFTH copy of the same information, free to drift from the four that
// already did.
//
// So the names come out of `Wrap` and `WrapTest` themselves: the functions that
// do the exporting are the only authority on what is exported, and a rename
// inside them moves this list in the same commit.
//
// ⚠ WHAT THIS CANNOT SEE, stated because the gate's accuracy rests on it: a
// variable exported only in a MODE no entry of the matrix below selects. That
// is a false ABSENCE, which makes a correct recipe fail the gate — the loud
// direction rather than the silent one. `TestExportedNamesCoversEveryExport`
// closes it by reading this package's own sources and failing on any `export
// NAME=` whose name this does not return, so a new mode fails the test that
// owns it rather than a recipe somewhere else.
func ExportedNames() []string {
	seen := map[string]bool{}
	add := func(script string) {
		for _, m := range exportedRE.FindAllStringSubmatch(script, -1) {
			seen[m[1]] = true
		}
	}
	for _, o := range wrapModes() {
		add(Wrap(o))
	}
	for _, o := range testModes() {
		add(WrapTest(o))
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// wrapModes enumerates the build-wrapper configurations whose union is every
// variable a build can be handed.
//
// The axes are the ones `Wrap` actually branches on: the TARGET platform
// (wasip1 brings its own sysroot variables, darwin brings the OSO prefix and no
// shims, windows is the cross case), LibcZpkx (the sovereign glibc mode, which
// is where CC/CXX and the whole ZPKB_GLIBC_* family come from), and PrefixMap
// (empty means no `-ffile-prefix-map`, so the two prefix variables would never
// appear).
func wrapModes() []WrapOptions {
	linux := target.Target{Platform: "linux", Arch: "x86-64", Triple: "x86_64-unknown-linux-gnu"}
	linuxArm := target.Target{Platform: "linux", Arch: "aarch64", Triple: "aarch64-unknown-linux-gnu"}
	darwin := target.Target{Platform: "darwin", Arch: "aarch64", Triple: "aarch64-apple-darwin"}
	windows := target.Target{Platform: "windows", Arch: "x86-64", Triple: "x86_64-pc-windows-gnu"}
	wasi := target.Target{Platform: "wasip1", Arch: "wasm", Triple: "wasm32-wasip1"}

	base := WrapOptions{
		SrcRoot:   "/build/src",
		Home:      "/build/home",
		ZpkgDir:   "/zpkg",
		Install:   "/zpkg/acme.org/v1.0.0",
		Project:   "acme.org",
		ShimPath:  "/libexec",
		ZpkxBin:   "/bin/zpkx",
		PrefixMap: "/build=/build",
	}
	var out []WrapOptions
	for _, t := range []target.Target{linux, linuxArm, darwin, windows, wasi} {
		for _, libc := range []bool{false, true} {
			o := base
			o.Target = t
			o.Host = t
			o.LibcZpkx = libc
			out = append(out, o)
			// A pinned glibc selects a different arm of the sysroot flags than
			// "newest available" does.
			if libc {
				o.Glibc = "2.27.0"
				out = append(out, o)
			}
		}
	}
	// No prefix map: the one axis that REMOVES variables rather than adding
	// them, kept so the union is not accidentally dependent on it.
	noMap := base
	noMap.Target, noMap.Host = linux, linux
	noMap.PrefixMap = ""
	out = append(out, noMap)
	// A build that already has a compiler, the first generation on an
	// architecture no registry carries, and a build with binutils among its
	// dependencies: each changes which evals and which tool variables are
	// emitted.
	//
	// ⛔ CROSSED WITH THE PLATFORM, because one of them is platform-gated and
	// the first version of this matrix was not: `HasBinutils` emits AR and
	// RANLIB only inside `if tgt.Platform == "darwin"` (wrapper.go:801-805), so
	// pairing it with linux alone left RANLIB out of the set — and
	// TestExportedNamesCoversEveryExport failed on exactly that, on its first
	// run, which is the whole reason that test reads the sources.
	for _, t := range []target.Target{linux, darwin} {
		for _, f := range []func(*WrapOptions){
			func(o *WrapOptions) { o.HasCompiler = true },
			func(o *WrapOptions) { o.Bootstrap = true },
			func(o *WrapOptions) { o.HasBinutils = true },
		} {
			o := base
			o.Target, o.Host = t, t
			o.LibcZpkx = true
			f(&o)
			out = append(out, o)
		}
	}
	return out
}

// testModes enumerates the test-sandbox configurations, on the axes WrapTest
// branches on: whether the test asks for a compiler, and whether the shim
// directory exists (empty means the flags go into $CC instead).
func testModes() []TestWrapOptions {
	host := target.Target{Platform: "linux", Arch: "x86-64", Triple: "x86_64-unknown-linux-gnu"}
	darwin := target.Target{Platform: "darwin", Arch: "aarch64", Triple: "aarch64-apple-darwin"}
	base := TestWrapOptions{
		Package: "acme.org@1.0.0",
		Home:    "/test/home",
		Sandbox: "/test/sandbox",
		ZpkgDir: "/zpkg",
		ZpkxBin: "/bin/zpkx",
		// Set, so the exports WrapTest makes for the build under test are
		// enumerated — a test script exports LD_LIBRARY_PATH for it.
		PackagePrefix: "/zpkg/acme.org/v1.0.0",
	}
	var out []TestWrapOptions
	for _, h := range []target.Target{host, darwin} {
		for _, compiler := range []bool{false, true} {
			for _, shim := range []string{"", "/libexec"} {
				o := base
				o.Host = h
				o.Compiler = compiler
				o.ShimDir = shim
				out = append(out, o)
			}
		}
	}
	return out
}

// OurEnvPrefixes are the namespaces a recipe may only read a variable from if
// this builder exports it.
//
// ⛔ THE DEAD SPELLINGS ARE LISTED ON PURPOSE. `ZBK_`, `BK_`, `BREWKIT_` and
// `PKGX_` name no variable any more — they are what the live ones used to be
// called — so every reference to one is a stale consumer of a rename by
// construction, and listing them is what makes the gate catch exactly the four
// instances that produced it. They cannot collide with a live name: nothing
// under these prefixes is exported, so the check's own test asserts the set is
// empty of them.
//
// ⚠ A prefix test rather than a shell-wide one, deliberately. An unknown
// `$HOMEBREW_WHATEVER` or `$ACLOCAL_PATH` in a recipe is the project's
// business, and refusing it would make this a shell linter with an opinion
// about other people's build systems. A misspelt name under one of these is
// always ours and always a defect.
var OurEnvPrefixes = []string{"ZPKB_", "ZPKG_", "ZBK_", "BK_", "BREWKIT_", "PKGX_"}
