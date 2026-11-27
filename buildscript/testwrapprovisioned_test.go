package buildscript

import (
	"slices"
	"strings"
	"testing"
)

// Under a seed the caller installs the test closure: Specs names it, and the
// script evaluates the returned environment and runs no zpkx for packages.
func TestWrapTestProvisionedEvaluatesTheEnvironmentAndAsksZpkxForNothing(t *testing.T) {
	o := TestWrapOptions{
		UserScript: "true", Package: "p.org@1", Deps: []string{"dep.org@^2"},
		Home: "/h", Sandbox: "/box", ZpkxBin: "/bin/zpkx", Host: linuxHost(),
	}
	if got, want := o.Specs(), []string{"p.org@1", "dep.org@^2"}; !slices.Equal(got, want) {
		t.Fatalf("Specs() = %v, want %v", got, want)
	}
	o.Provisioned, o.Env = true, "PATH='/x/bin'"
	s := WrapTest(o)
	if !strings.Contains(s, "eval 'PATH='\\''/x/bin'\\'''") {
		t.Errorf("the provisioned environment is not evaluated:\n%s", s)
	}
	if strings.Contains(s, `"+p.org@1"`) || strings.Contains(s, "__bk_deps_env") {
		t.Errorf("the script still asks zpkx for packages:\n%s", s)
	}
}
