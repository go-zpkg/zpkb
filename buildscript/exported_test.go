package buildscript

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestExportedNamesCoversEveryExport is the test that owns the matrix in
// wrapModes/testModes.
//
// ⛔⛔ IT READS THIS PACKAGE'S OWN SOURCE, which is unusual and is the point.
// ExportedNames derives its answer by RENDERING the wrapper in a list of modes,
// so a variable exported only in a mode that list does not select is invisible
// to it — and then `zpkb lint` would refuse a correct recipe for reading a
// variable the builder really does provide. That failure would surface far from
// its cause, in another repository's lane, about somebody else's recipe.
//
// Reading the sources closes it HERE: every `export NAME=` written in this
// package must be a name ExportedNames returns, so adding a variable behind a
// new flag fails this test, in the package that added it, in the same commit.
//
// It parses rather than greps, so that `export NAME=` written in a COMMENT —
// this file and exported.go both contain examples — cannot invent a
// requirement. Only STRING LITERALS count, because only a string literal can
// reach a build script.
func TestExportedNamesCoversEveryExport(t *testing.T) {
	known := map[string]bool{}
	for _, n := range ExportedNames() {
		known[n] = true
	}
	// A floor: a run that parsed nothing must not read as a clean one.
	// go-zpkg/zpkb#494's own cause was a search that could not match its
	// target reporting zero.
	literals := 0
	var missing []string
	for _, src := range packageSources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, src, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", src, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			literals++
			for _, m := range exportedRE.FindAllStringSubmatch(s, -1) {
				if !known[m[1]] {
					missing = append(missing,
						m[1]+" ("+filepath.Base(src)+":"+strconv.Itoa(fset.Position(lit.Pos()).Line)+")")
				}
			}
			return true
		})
	}
	if literals == 0 {
		t.Fatal("no string literal was read: this test measured nothing")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("ExportedNames() misses %d name(s) this package exports, so "+
			"`zpkb lint` would refuse a recipe that reads one:\n  %s\n"+
			"Add the mode that emits it to wrapModes()/testModes() in exported.go.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestExportedNamesHoldsTheLiveSpellingAndNotTheDeadOne is the pair from
// go-zpkg/recipes#138: the kernel recipe passed
// `CC="$ZBK_CC_FREESTANDING"` to make while the builder exports
// `ZPKB_CC_FREESTANDING`, so the kernel compiled with an empty CC.
//
// Both halves are asserted, because only the pair proves the list discriminates:
// a set containing everything would satisfy the first assertion alone.
func TestExportedNamesHoldsTheLiveSpellingAndNotTheDeadOne(t *testing.T) {
	known := map[string]bool{}
	for _, n := range ExportedNames() {
		known[n] = true
	}
	if !known["ZPKB_CC_FREESTANDING"] {
		t.Error("ZPKB_CC_FREESTANDING is exported by wrapper.go and is not in the set")
	}
	if known["ZBK_CC_FREESTANDING"] {
		t.Error("ZBK_CC_FREESTANDING is a dead spelling and must not be in the set")
	}
	// The whole dead-prefix family, so a future rename cannot leave one behind.
	for _, n := range ExportedNames() {
		for _, p := range []string{"ZBK_", "BK_", "BREWKIT_", "PKGX_"} {
			if strings.HasPrefix(n, p) {
				t.Errorf("%q is exported under the dead prefix %q", n, p)
			}
		}
	}
}

// TestExportedNamesHoldsTheFamiliesRecipesRead pins the names recipes in our
// own trees actually depend on. They are asserted individually rather than by
// count: a count moves whenever a variable is added, and would be edited
// without being read.
func TestExportedNamesHoldsTheFamiliesRecipesRead(t *testing.T) {
	known := map[string]bool{}
	for _, n := range ExportedNames() {
		known[n] = true
	}
	for _, n := range []string{
		"CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS",
		"ZPKB_CC", "ZPKB_CXX", "ZPKB_CC_FREESTANDING",
		"ZPKB_GLIBC_PREFIX", "ZPKB_KHDR_PREFIX",
		"ZPKB_WASI_SYSROOT", "ZPKB_WASI_CXX",
		"ZPKB_FILE_PREFIX_MAP",
	} {
		if !known[n] {
			t.Errorf("%s is not in ExportedNames(); wrapModes()/testModes() does not "+
				"select the mode that exports it", n)
		}
	}
}

// packageSources lists this package's non-test .go files. The test files are
// excluded because their literals are ASSERTIONS about the preamble, not the
// preamble: wrapper_test.go holds `export CC="${CC:-clang …` as an expected
// substring, and a copy of a thing is not the thing.
func packageSources(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		t.Fatal("no source file found in the package directory")
	}
	sort.Strings(out)
	return out
}
