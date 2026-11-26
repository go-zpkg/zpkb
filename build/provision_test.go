package build

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// Under a seed the factory composes both environments itself and the script
// evaluates them: the closures are asked for with their specs, tools and
// dependencies separately, and the script never calls zpkx for packages.
func TestBuildProvisionedScriptEvaluatesWhatTheFactoryComposed(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script":       []any{"make install"},
		"dependencies": map[string]any{"gnu.org/make": "*"},
	}
	r := okRunner("acme.org/tool", tgt)
	r.ResolveDep = func(string, string) (string, error) { return "1.0.0", nil }
	var asked [][]string
	r.Provision = func(specs []string) (string, error) {
		asked = append(asked, specs)
		return "PROVISIONED=" + strings.Join(specs, ","), nil
	}
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) == 0 {
		t.Fatal("the provisioner was never asked")
	}
	b, _ := os.ReadFile(res.ScriptPath)
	s := string(b)
	if strings.Contains(s, "__bk_deps_env") {
		t.Errorf("a provisioned script must not ask zpkx for packages:\n%s", s)
	}
	if !strings.Contains(s, "eval 'PROVISIONED=") {
		t.Errorf("the composed environment is not in the script:\n%s", s)
	}
}

func TestBuildProvisionFailureNamesTheClosure(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script":       []any{"make install"},
		"dependencies": map[string]any{"gnu.org/make": "*"},
	}
	for _, failOn := range []int{1, 2} { // the tool closure, then the dependency one
		r := okRunner("acme.org/tool", tgt)
		r.ResolveDep = func(string, string) (string, error) { return "1.0.0", nil }
		n := 0
		r.Provision = func([]string) (string, error) {
			n++
			if n == failOn {
				return "", errBoom
			}
			return "X=1", nil
		}
		_, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
		if err == nil || !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "environment failed") {
			t.Errorf("failure %d: err = %v", failOn, err)
		}
	}
}

func TestProvisionOfNothingAsksNothing(t *testing.T) {
	r := &Runner{Provision: func([]string) (string, error) { t.Fatal("asked"); return "", nil }}
	if env, err := r.provision(nil, "tool"); env != "" || err != nil {
		t.Fatalf("%q %v", env, err)
	}
}
