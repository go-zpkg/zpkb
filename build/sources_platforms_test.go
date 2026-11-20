package build

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

func platSrc(url string, platforms any) map[string]any {
	m := map[string]any{"url": url, "sha256": digA}
	if platforms != nil {
		m["platforms"] = platforms
	}
	return m
}

func TestSourcePlatformsRefuseAnUnknownSpelling(t *testing.T) {
	for _, bad := range []any{"plan9", []any{"linux/x86_64"}, []any{"linux/wasm"}, []any{}, []any{1}, 7} {
		if _, err := extraSourcesOf([]any{platSrc("https://x/a.tar.gz", bad)}, "1.0", ""); err == nil {
			t.Errorf("platforms %v accepted", bad)
		}
	}
	got, err := extraSourcesOf([]any{platSrc("https://x/a.tar.gz", []any{"linux/x86-64", "darwin"})}, "1.0", "")
	if err != nil || got[0].platforms == nil {
		t.Errorf("good spelling: %+v, %v", got, err)
	}
}

func buildWithPlatformSources(t *testing.T, tgt target.Target, srcs ...any) ([]string, SourceRef, error) {
	t.Helper()
	tenv(t)
	defer func() { logf = origLogf }()
	logf = func(string, ...any) {}
	r, calls := srcsRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Sources = srcs
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")
	return *calls, res.Source, err
}

// Only the matching entries are fetched, an unrestricted entry keeps its old
// meaning, and provenance (Source.Extra) lists exactly what was fetched.
func TestBuildFetchesOnlyTheSourcesMatchingTheTarget(t *testing.T) {
	srcs := []any{
		platSrc("https://x/go-linux-amd64.tar.gz", []any{"linux/x86-64"}),
		platSrc("https://x/go-darwin-arm64.tar.gz", []any{"darwin/aarch64"}),
		platSrc("https://x/go-linux-any.tar.gz", "linux"),
		platSrc("https://x/common.tar.gz", nil),
	}
	calls, src, err := buildWithPlatformSources(t, target.Target{Platform: "linux", Arch: "x86-64"}, srcs...)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "|")
	if strings.Contains(joined, "darwin") || !strings.Contains(joined, "go-linux-amd64") ||
		!strings.Contains(joined, "go-linux-any") || !strings.Contains(joined, "common") {
		t.Errorf("calls = %v", calls)
	}
	want := []SourceRef{
		{URI: "https://x/go-linux-amd64.tar.gz", SHA256: digA},
		{URI: "https://x/go-linux-any.tar.gz", SHA256: digA},
		{URI: "https://x/common.tar.gz", SHA256: digA},
	}
	if !reflect.DeepEqual(src.Extra, want) {
		t.Errorf("materials = %+v, want %+v", src.Extra, want)
	}
}

// A target that no restricted entry covers is refused, naming the target, and
// nothing is fetched for it.
func TestBuildRefusesATargetNoRestrictedSourceCovers(t *testing.T) {
	srcs := []any{platSrc("https://x/go-linux-amd64.tar.gz", []any{"linux/x86-64"})}
	calls, _, err := buildWithPlatformSources(t, target.Target{Platform: "darwin", Arch: "aarch64"}, srcs...)
	if err == nil || !strings.Contains(err.Error(), "darwin/aarch64") {
		t.Fatalf("err = %v, want a refusal naming darwin/aarch64", err)
	}
	for _, c := range calls {
		if strings.Contains(c, "go-linux") {
			t.Errorf("fetched %s for a target it does not cover", c)
		}
	}
}

// An unrestricted entry alone never triggers the refusal: no entry restricts.
func TestUnrestrictedSourcesAreNeverRefused(t *testing.T) {
	got, err := selectSources([]source{{url: "u"}}, "windows", "aarch64")
	if err != nil || len(got) != 1 {
		t.Errorf("got %v, %v", got, err)
	}
	// Restricted entries alongside an unrestricted one still need a cover.
	_, err = selectSources([]source{{url: "u"}, {url: "v", platforms: []any{"linux"}}}, "windows", "aarch64")
	if err == nil {
		t.Error("an uncovered target was accepted because an unrestricted entry exists")
	}
}
