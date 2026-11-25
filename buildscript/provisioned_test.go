package buildscript

import (
	"strings"
	"testing"
)

// A provisioned script never calls zpkx for packages: the factory composed the
// environments and the script evaluates them, tools first.
func TestWrapProvisionedEvaluatesTheComposedEnvAndCallsNoZpkx(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make",
		Deps:       []string{"zlib.net"}, ToolDeps: []string{"nodejs.org"},
		Target: darwinTgt(), Host: darwinTgt(), ZpkxBin: "/bin/zpkx-unused",
		Provisioned: true, ToolEnv: "TOOL=1", DepEnv: "DEP=it's",
	})
	if strings.Contains(s, "__bk_deps_env") || strings.Contains(s, "environment failed") {
		t.Fatalf("a provisioned script still asks zpkx for packages:\n%s", s)
	}
	tool := strings.Index(s, "eval 'TOOL=1'")
	dep := strings.Index(s, `eval 'DEP=it'\''s'`)
	if tool < 0 || dep < 0 || tool > dep {
		t.Fatalf("tool env must be evaluated first, quotes escaped (tool=%d dep=%d):\n%s", tool, dep, s)
	}
}

// An unprovisioned script is the one it always was.
func TestWrapUnprovisionedKeepsAskingZpkx(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"zlib.net"}, ToolDeps: []string{"nodejs.org"},
		Target: darwinTgt(), Host: darwinTgt(), ZpkxBin: "/bin/zpkx-used",
		ToolEnv: "IGNORED=1", DepEnv: "IGNORED=2",
	})
	if !strings.Contains(s, "__bk_deps_env=\"$(CLICOLOR_FORCE=1 /bin/zpkx-used ") || strings.Contains(s, "IGNORED") {
		t.Fatalf("an unprovisioned script must call zpkx and ignore the literals:\n%s", s)
	}
}

func TestWriteEnvLiteralEmptyWritesNothing(t *testing.T) {
	var b strings.Builder
	writeEnvLiteral(&b, "")
	if b.String() != "" {
		t.Fatalf("empty env wrote %q", b.String())
	}
}

func TestSpecsAreTheClosuresWithoutQuotesOrPlus(t *testing.T) {
	o := WrapOptions{
		Deps: []string{"zlib.net^1"}, ToolDeps: []string{"nodejs.org", "gnu.org/autoconf"},
		Target: darwinTgt(), Host: darwinTgt(),
	}
	if got := strings.Join(o.ToolSpecs(), " "); got != "nodejs.org gnu.org/autoconf" {
		t.Errorf("ToolSpecs = %q", got)
	}
	if got := o.DepSpecs(); len(got) == 0 || got[0] != "zlib.net^1" {
		t.Errorf("DepSpecs = %q", got)
	}
	if specsOf("") != nil {
		t.Error("no specs must be nil")
	}
}
