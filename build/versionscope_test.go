package build

import (
	"reflect"
	"testing"
)

// TestVersionScopeIsNotRangeRE is the regression witness for the mistake this
// feature was one keystroke away from shipping.
//
// buildscript has `rangeRE = ^[v0-9*^~<>=]` and it already classifies an `if:`
// condition as a version range. Reusing it for DEPENDENCY keys would read every
// project whose name begins with `v` as a version predicate — and the upstream
// pantry has 26 of them. The key would then be dropped or merged as a scope
// instead of naming a project, which is silent in both directions.
//
// The names below are real projects from pkgxdev/pantry.
func TestVersionScopeIsNotRangeRE(t *testing.T) {
	projects := []string{
		"valgrind.org", "vitejs.dev", "videolan.org", "vim.org", "vtk.org",
		"volta.sh", "vlang.io", "vector.dev", "vale.sh", "valkey.io",
		"v2raya.org", "vapoursynth.com", "vaultproject.io", "visidata.org",
		"virtualenv.pypa.io", "victoriametrics.com",
	}
	for _, p := range projects {
		if isScope, _ := versionScope(p, "1.0.0"); isScope {
			t.Errorf("versionScope(%q) read a PROJECT as a version scope", p)
		}
	}
	// And a bare dotted version IS a legal depKey, so it stays a project. The
	// doc comment says to write `=5.40`; this pins that statement.
	if isScope, _ := versionScope("5.40", "1.0.0"); isScope {
		t.Error(`versionScope("5.40") read a bare version as a scope; the grammar says a scope carries an operator`)
	}
}

func TestVersionScopeRecognisesOperators(t *testing.T) {
	for _, k := range []string{"<18", ">=3", "^2", "~3.5", "*", ">=3<3.12", "=5.40"} {
		if isScope, _ := versionScope(k, "1.0.0"); !isScope {
			t.Errorf("versionScope(%q) did not recognise a version scope", k)
		}
	}
}

func TestVersionScopeSatisfaction(t *testing.T) {
	cases := []struct {
		key, ver string
		want     bool
	}{
		{"<18", "17.0.6", true},
		{"<18", "23.1.5", false},
		{">=3<3.12", "3.11.9", true},
		{">=3<3.12", "3.15.2", false},
		{"^2", "2.15.0", true},
		{"^2", "3.0.0", false},
	}
	for _, c := range cases {
		isScope, ok := versionScope(c.key, c.ver)
		if !isScope {
			t.Fatalf("versionScope(%q) is not a scope", c.key)
		}
		if ok != c.want {
			t.Errorf("versionScope(%q, %q) = %v, want %v", c.key, c.ver, ok, c.want)
		}
	}
}

// ⛔ An unknown version UNIONS, and an unparseable one FAILS OPEN. Both are the
// conservative direction for a closure — see versionScope's own comment — and
// both are asserted because a later "simplification" to fail closed would make
// a build silently miss a library rather than loudly install a spare one.
func TestVersionScopeUnknownAndUnparseableInclude(t *testing.T) {
	if isScope, ok := versionScope("<18", ""); !isScope || !ok {
		t.Errorf(`versionScope("<18", "") = %v, %v; an unknown version must UNION`, isScope, ok)
	}
	if isScope, ok := versionScope("<18", "not-a-version"); !isScope || !ok {
		t.Errorf(`versionScope("<18", %q) = %v, %v; an unparseable version must fail OPEN`, "not-a-version", isScope, ok)
	}
}

// TestReduceDepsAtScopes is the end-to-end shape a recipe writes: the llvm case
// that motivated the feature (go-zpkg/zpkb#488).
func TestReduceDepsAtScopes(t *testing.T) {
	deps := map[string]any{
		"python.org": ">=3",
		"<18": map[string]any{
			"python.org": ">=3<3.12",
		},
	}

	// The version the bound was written for keeps the tight constraint.
	if got := ReduceDepsAt(deps, lin(), "17.0.6"); got["python.org"] != ">=3<3.12" {
		t.Errorf("at 17.0.6 python.org = %q, want the scoped bound", got["python.org"])
	}

	// ⭐ THE WHOLE POINT: the newest version is no longer held to it. LLVM
	// 23.1.5's own CMakeLists sets LLVM_MINIMUM_PYTHON_VERSION 3.8 with no
	// ceiling, and before this change the recipe had no way to say so.
	if got := ReduceDepsAt(deps, lin(), "23.1.5"); got["python.org"] != ">=3" {
		t.Errorf("at 23.1.5 python.org = %q, want the unscoped constraint", got["python.org"])
	}

	// And with no version in hand the scope is unioned, so a closure walk sees
	// the tighter constraint rather than missing the dependency.
	if got := ReduceDeps(deps, lin()); got["python.org"] != ">=3<3.12" {
		t.Errorf("unioned python.org = %q, want the scoped bound to be included", got["python.org"])
	}
}

// A platform key and a version scope must not interfere: the platform is tested
// first, and neither spelling can be mistaken for the other because a platform
// key cannot hold an operator character.
func TestReduceDepsAtPlatformAndVersionTogether(t *testing.T) {
	deps := map[string]any{
		"zlib.net": "^1",
		"linux": map[string]any{
			"github.com/besser82/libxcrypt": "^4",
		},
		"<2": map[string]any{
			"gnu.org/m4": "^1",
		},
	}
	got := ReduceDepsAt(deps, lin(), "1.9.0")
	want := map[string]string{
		"zlib.net":                      "^1",
		"github.com/besser82/libxcrypt": "^4",
		"gnu.org/m4":                    "^1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("at 1.9.0 = %v, want %v", got, want)
	}

	// Past the scope, only the platform entry survives beside the plain one.
	got = ReduceDepsAt(deps, lin(), "2.0.0")
	delete(want, "gnu.org/m4")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("at 2.0.0 = %v, want %v", got, want)
	}
}

// ⛔⛔ THE WITNESS FOR A NON-DETERMINISM THAT PREDATES VERSION SCOPES.
//
// A recipe may name one project plainly AND under a platform key. Both write
// the same slot, so a single pass over the map let Go's randomised iteration
// order decide the winner — the same recipe could reduce differently between
// two runs of the same binary. reduceDepMap now makes three ordered passes, so
// "more specific wins" is a rule instead of an accident.
//
// Run with -count high enough and a one-pass implementation fails this; it is
// the reason the passes exist.
func TestReduceDepsPlatformOverridesPlainDeterministically(t *testing.T) {
	deps := map[string]any{
		"zlib.net": "^1",
		"linux": map[string]any{
			"zlib.net": "^1.2",
		},
	}
	for i := 0; i < 200; i++ {
		if got := ReduceDeps(deps, lin())["zlib.net"]; got != "^1.2" {
			t.Fatalf("iteration %d: zlib.net = %q, want the platform entry to win every time", i, got)
		}
	}
}

// And the same collision between a plain key and a version scope.
func TestReduceDepsAtScopeOverridesPlainDeterministically(t *testing.T) {
	deps := map[string]any{
		"python.org": ">=3",
		"<18": map[string]any{
			"python.org": ">=3<3.12",
		},
	}
	for i := 0; i < 200; i++ {
		if got := ReduceDepsAt(deps, lin(), "17.0.0")["python.org"]; got != ">=3<3.12" {
			t.Fatalf("iteration %d: python.org = %q, want the scope to win every time", i, got)
		}
	}
}

// DepSpecsAt and EvalLinkDepsAt must carry the same reduction, because the
// artefact's @rpath references come from the link set: a scope that leaked
// through here would record a dependency the recipe does not state for that
// version.
func TestEvalLinkDepsAtHonoursTheScope(t *testing.T) {
	deps := map[string]any{
		"zlib.net": "^1",
		"<18": map[string]any{
			"gnome.org/libxml2": "^2",
		},
	}
	if got := EvalLinkDepsAt(deps, lin(), "17.0.0"); !reflect.DeepEqual(got, []string{"gnome.org/libxml2^2", "zlib.net^1"}) {
		t.Errorf("at 17 link deps = %v", got)
	}
	if got := EvalLinkDepsAt(deps, lin(), "23.1.5"); !reflect.DeepEqual(got, []string{"zlib.net^1"}) {
		t.Errorf("at 23 link deps = %v, want libxml2 dropped", got)
	}
}
