package build

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

const (
	digA = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
	digB = "cc0b4e42510d49c6decd464123ecf3b14ae9b47f9b4ed2ee64893e2d6520a264"
)

func TestExtraSourcesOf(t *testing.T) {
	ok := func(m map[string]any) []any { return []any{m} }
	good := map[string]any{"url": "https://x/tk-{{version}}.tar.gz", "sha256": digA}

	t.Run("none", func(t *testing.T) {
		got, err := extraSourcesOf(nil, "1.2.3", "")
		if err != nil || got != nil {
			t.Errorf("got %v, %v", got, err)
		}
	})

	t.Run("a good entry, defaults and moustaches", func(t *testing.T) {
		got, err := extraSourcesOf(ok(good), "1.2.3", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].url != "https://x/tk-1.2.3.tar.gz" || got[0].dest != "." ||
			got[0].sha256 != digA || got[0].file || got[0].strip != 0 {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("every field, version.tag, a keyed digest", func(t *testing.T) {
		got, err := extraSourcesOf(ok(map[string]any{
			"url":     "https://x/{{version.tag}}/fix.patch",
			"sha256":  map[string]any{"1.2.3": digB},
			"dest":    "patches/{{version}}",
			"extract": false,
		}), "1.2.3", "rel-1")
		if err != nil {
			t.Fatal(err)
		}
		s := got[0]
		if s.url != "https://x/rel-1/fix.patch" || s.dest != "patches/1.2.3" || !s.file || s.sha256 != digB {
			t.Errorf("got %+v", s)
		}
	})

	t.Run("an empty tag falls back to the version", func(t *testing.T) {
		got, err := extraSourcesOf(ok(map[string]any{"url": "https://x/{{version.tag}}.tar.gz", "sha256": digA}), "1.2.3", "")
		if err != nil || got[0].url != "https://x/1.2.3.tar.gz" {
			t.Errorf("got %+v, %v", got, err)
		}
	})

	for _, c := range []struct {
		name string
		in   any
		want string
	}{
		{"a map, not a list", map[string]any{"url": "u"}, "non-empty list"},
		{"an empty list", []any{}, "non-empty list"},
		{"a string entry has nowhere to put a digest", []any{"https://x/a.tar.gz"}, "must be a map"},
		{"no sha256", ok(map[string]any{"url": "https://x/a.tar.gz"}), "sha256 is required"},
		{"no url", ok(map[string]any{"sha256": digA}), "no url"},
		{"a git ref", ok(map[string]any{"url": "https://x/r", "ref": "v1", "sha256": digA}), "git ref"},
		{"a malformed digest", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": "abc"}), "not a lowercase hex"},
		{"a keyed digest without this version", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": map[string]any{"9.9": digA}}), "not for 1.2.3"},
		{"dest escaping the build dir", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": digA, "dest": "../out"}), "inside the build directory"},
		{"an absolute dest", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": digA, "dest": "/etc"}), "inside the build directory"},
		{"an empty dest", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": digA, "dest": ""}), "inside the build directory"},
		{"a non-string dest", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": digA, "dest": 3}), "dest must be a string"},
		{"a non-boolean extract", ok(map[string]any{"url": "https://x/a.tar.gz", "sha256": digA, "extract": "no"}), "extract must be"},
		{"strip-components on a plain file", ok(map[string]any{"url": "https://x/a.pem", "sha256": digA, "extract": false, "strip-components": 1}), "strip-components"},
		{"the second entry is the bad one", []any{good, map[string]any{"url": "https://x/b.tar.gz"}}, "sources[1]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := extraSourcesOf(c.in, "1.2.3", "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestAPlainFileDistributable(t *testing.T) {
	toks := func(m map[string]any) (source, error) { return oneSource(m, "1.2.3", nil) }

	s, err := toks(map[string]any{"url": "https://curl.se/ca/cacert.pem", "sha256": digA, "extract": false})
	if err != nil || !s.file {
		t.Fatalf("got %+v, %v", s, err)
	}
	// extract: true is the default spelt out.
	if s, err := toks(map[string]any{"url": "https://x/a.tar.gz", "extract": true}); err != nil || s.file {
		t.Errorf("got %+v, %v", s, err)
	}
	for _, c := range []struct {
		name string
		m    map[string]any
		want string
	}{
		{"no digest", map[string]any{"url": "https://x/c.pem", "extract": false}, "must pin a sha256"},
		{"strip-components", map[string]any{"url": "https://x/c.pem", "extract": false, "sha256": digA, "strip-components": 1}, "strip-components"},
		{"a git ref", map[string]any{"url": "https://x/c", "extract": false, "sha256": digA, "ref": "v1"}, "cannot be combined"},
		{"not a boolean", map[string]any{"url": "https://x/c.pem", "extract": 0}, "extract must be"},
	} {
		if _, err := toks(c.m); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

func srcsRunner(project string, tgt target.Target) (*Runner, *[]string) {
	var calls []string
	r := okRunner(project, tgt)
	r.Fetch = func(url, dest string, strip int) (string, error) {
		calls = append(calls, "archive "+url+" "+filepath.Base(dest))
		return digA, nil
	}
	r.FetchFile = func(url, dest string) (string, error) {
		calls = append(calls, "file "+url+" "+filepath.Base(dest))
		return digB, nil
	}
	return r, &calls
}

func TestBuildFetchesEverySource(t *testing.T) {
	tenv(t)
	defer func() { logf = origLogf }()
	logf = func(string, ...any) {}
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r, calls := srcsRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Sources = []any{
		map[string]any{"url": "https://x/tk.tar.gz", "sha256": digA, "dest": "tk", "strip-components": 1},
		map[string]any{"url": "https://x/fix.patch", "sha256": digB, "extract": false},
	}
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")
	if err != nil {
		t.Fatal(err)
	}
	// The distributable is first, then EVERY source in order — a mirror list
	// would have stopped after one.
	want := []string{"archive https://x/v1.2.3.tar.gz build", "archive https://x/tk.tar.gz tk", "file https://x/fix.patch build"}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", *calls, want)
	}
	wantExtra := []SourceRef{{URI: "https://x/tk.tar.gz", SHA256: digA}, {URI: "https://x/fix.patch", SHA256: digB}}
	if !reflect.DeepEqual(res.Source.Extra, wantExtra) {
		t.Errorf("extra = %+v", res.Source.Extra)
	}
	if res.Source.URI != "https://x/v1.2.3.tar.gz" {
		t.Errorf("main source = %+v", res.Source)
	}
}

func TestSourcesDoNotNeedADistributable(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r, calls := srcsRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Distributable = nil
	rec.Sources = []any{map[string]any{"url": "https://x/a.zip", "sha256": digA}}
	if _, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, ""); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Errorf("calls = %v", *calls)
	}
}

// ⛔ The list form of distributable is still MIRRORS: this is the property the
// issue's correction turned on, so it is asserted next to the new key.
func TestADistributableListStillStopsAtTheFirstMirror(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r, calls := srcsRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Distributable = []any{
		map[string]any{"url": "https://a/x.tar.gz"},
		map[string]any{"url": "https://b/x.tar.gz"},
	}
	if _, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, ""); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Errorf("a list distributable fetched %d sources, want 1: %v", len(*calls), *calls)
	}
}

func TestAPlainFileDistributableIsCopied(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r, calls := srcsRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Distributable = map[string]any{"url": "https://curl.se/ca/cacert.pem", "sha256": digB, "extract": false}
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || !strings.HasPrefix((*calls)[0], "file ") || res.Source.SHA256 != digB {
		t.Errorf("calls = %v, source = %+v", *calls, res.Source)
	}
}

func TestASourceFailureFailsTheBuild(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	two := func() *pantry.Recipe {
		rec := okRecipe()
		rec.Sources = []any{
			map[string]any{"url": "https://x/a.tar.gz", "sha256": digA},
			map[string]any{"url": "https://x/b.patch", "sha256": digA, "extract": false},
		}
		return rec
	}

	t.Run("a digest mismatch, on an archive", func(t *testing.T) {
		tenv(t)
		r, _ := srcsRunner("acme.org/tool", tgt)
		r.Fetch = func(string, string, int) (string, error) { return digB, nil }
		rec := okRecipe()
		rec.Distributable = nil
		rec.Sources = []any{map[string]any{"url": "https://x/a.tar.gz", "sha256": digA}}
		_, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("err = %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("a digest mismatch, on a plain file", func(t *testing.T) {
		tenv(t)
		r, _ := srcsRunner("acme.org/tool", tgt) // FetchFile answers digB; the pin is digA
		if _, err := r.Build(two(), "acme.org/tool", "*", tgt, tgt, ""); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("err = %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("a fetch error is not skipped", func(t *testing.T) {
		tenv(t)
		r, _ := srcsRunner("acme.org/tool", tgt)
		r.FetchFile = func(string, string) (string, error) { return "", errBoom }
		_, err := r.Build(two(), "acme.org/tool", "*", tgt, tgt, "")
		if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "b.patch") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an invalid sources key stops before building", func(t *testing.T) {
		tenv(t)
		r, calls := srcsRunner("acme.org/tool", tgt)
		rec := okRecipe()
		rec.Sources = []any{map[string]any{"url": "https://x/a.tar.gz"}}
		if _, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, ""); err == nil || !strings.Contains(err.Error(), "sha256 is required") {
			t.Fatalf("err = %v", err)
		}
		if len(*calls) != 1 { // only the distributable ran
			t.Errorf("calls = %v", *calls)
		}
	})

	t.Run("touching the tree after the sources fails", func(t *testing.T) {
		tenv(t)
		r, _ := srcsRunner("acme.org/tool", tgt)
		n := 0
		r.Touch = func(string) error {
			n++
			if n == 2 {
				return errBoom
			}
			return nil
		}
		rec := okRecipe()
		rec.Sources = []any{map[string]any{"url": "https://x/a.tar.gz", "sha256": digA}}
		if _, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, ""); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
}
