package main

import (
	"reflect"
	"strings"
	"testing"
)

// What counts is the issue's own definition (go-zpkg/zpkb#487), and each row is
// one of its stated cases.
func TestScriptFetchesCountsWhatTheIssueCounted(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  map[string]any
		want int
	}{
		{"curl", bd("curl -L https://x.org/a.tar.gz | tar x"), 1},
		{"wget", bd("wget https://x.org/a.tar.gz"), 1},
		{"git clone", bd("git clone https://x.org/a.git"), 1},
		{"svn checkout", bd("svn checkout https://x.org/a"), 1},
		{"hg clone", bd("hg clone https://x.org/a"), 1},
		{"inside a subshell", bd("X=$(curl -s https://x.org/v)"), 1},
		// ⛔ the 549 -> 113 correction: these build the source the builder already
		// fetched and pinned.
		{"cargo install", bd("cargo install --locked --path . --root {{prefix}}"), 0},
		{"pip install", bd("python -m pip install --prefix={{prefix}} ."), 0},
		{"npm install", bd("npm install"), 0},
		{"go install", bd("go install ./..."), 0},
		{"curl-config is not curl", bd("./curl-config --prefix"), 0},
		{"loopback", bd("curl http://127.0.0.1:1/"), 0},
		{"curl --version", bd("curl --version"), 0},
		{"a comment", bd("  # each was confirmed by a second fetch with curl.\nmake"), 0},
	} {
		got, _ := scriptFetches(tc.doc)
		if len(got) != tc.want {
			t.Errorf("%s: %d line(s), want %d: %v", tc.name, len(got), tc.want, got)
		}
	}
}

func bd(script string) map[string]any {
	return map[string]any{"build": map[string]any{"script": script}}
}

// The script may be a scalar, a list, or a list of {run} maps, and env is read
// too; judge and subject must count alike.
func TestScriptFetchesReadsEveryShapeOfBuild(t *testing.T) {
	docs := map[string]map[string]any{
		"scalar build": {"build": "curl https://x.org/a"},
		"list":         {"build": map[string]any{"script": []any{"make", "wget https://x.org/a"}}},
		"run map":      {"build": map[string]any{"script": []any{map[string]any{"run": "curl https://x.org/a"}}}},
		"env":          {"build": map[string]any{"env": map[string]any{"FETCH": "curl https://x.org/a"}, "script": "make"}},
	}
	for name, doc := range docs {
		if got, _ := scriptFetches(doc); len(got) != 1 {
			t.Errorf("%s: %v", name, got)
		}
	}
	if got, test := scriptFetches(map[string]any{}); got != nil || test != nil {
		t.Errorf("no build, no test: %v %v", got, test)
	}
}

// The test block is counted apart and never in the build's number.
func TestScriptFetchesSeparatesTheTest(t *testing.T) {
	b, tst := scriptFetches(map[string]any{
		"build": map[string]any{"script": "make"},
		"test":  map[string]any{"script": "curl https://x.org/a"},
	})
	if len(b) != 0 || len(tst) != 1 {
		t.Errorf("build %v test %v", b, tst)
	}
}

func TestFetchShapeNamesTheRemedy(t *testing.T) {
	for line, want := range map[string]string{
		"curl https://github.com/tesseract-ocr/tessdata/blob/main/eng.traineddata?raw=true": "floating",
		"curl https://github.com/o/r/archive/refs/heads/dev.tar.gz":                         "floating",
		"curl -L https://github.com/o/r/commit/7b26.patch | patch -p1":                      "patch",
		"curl $PATCH | patch -p1 || true":                                                   "patch",
		"curl -L https://x.org/tk-1.tar.xz | tar x":                                         "archive",
		"curl -o bun.sh https://bun.sh/install":                                             "other",
	} {
		if got := fetchShape(line); got != want {
			t.Errorf("%q: %s, want %s", line, got, want)
		}
	}
	if got := shapeSummary([]string{"curl a.patch", "curl a.tar.gz", "curl b.tar.gz", "curl x"}); got != "1 patch, 2 archive, 1 other" {
		t.Errorf("summary %q", got)
	}
	if got := shapeSummary([]string{"curl https://x/blob/main/f"}); got != "1 floating" {
		t.Errorf("summary %q", got)
	}
}

func TestStringsOfNodeIsDeterministic(t *testing.T) {
	m := map[string]any{"b": "2", "a": "1", "c": []any{"3"}}
	if got := stringsOfNode(m); !reflect.DeepEqual(got, []string{"1", "2", "3"}) {
		t.Errorf("%v", got)
	}
	if got := stringsOfNode(42); got != nil {
		t.Errorf("%v", got)
	}
}

// fetchTree is two recipes that fetch in the build (one of them twice), one that
// fetches only in a test, and one clean.
func fetchTree(t *testing.T) string {
	t.Helper()
	whole := "versions { github = \"c/c\" }\n" +
		"distributable { url = \"https://c.org/{{version}}.tar.gz\" }\n"
	return lintTree(t, map[string]string{
		"a.org/package.hcl": whole + "build { script = \"curl -L https://a.org/x.tar.gz | tar x\\nwget https://a.org/y.patch\" }\n",
		"b.org/package.hcl": whole + "build { script = \"git clone https://b.org/b.git\" }\n",
		"c.org/package.hcl": whole + "build { script = \"make install\" }\ntest { script = \"curl https://c.org/probe\" }\n",
		"d.org/package.hcl": whole + "build { script = \"make install\" }\n",
	})
}

func TestLintScriptFetchesAcceptsTheStatedNumber(t *testing.T) {
	rc, out, errb := lint(t, "--dir", fetchTree(t), "--max-script-fetches", "2")
	if rc != 0 {
		t.Fatalf("at the stated ceiling the run must pass: rc=%d\n%s", rc, errb)
	}
	if !strings.Contains(out, "script fetches: 2 recipe(s), 3 line(s) in the build; 1 recipe(s), 1 line(s) in a test only") {
		t.Errorf("the counts are missing: %q", out)
	}
	for _, want := range []string{"a.org", "2 line(s) (1 patch, 1 archive)", "b.org", "at the stated ceiling of 2"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q:\n%s", want, errb)
		}
	}
	// a test-only fetch is reported apart and never named as a build finding
	if strings.Contains(errb, "c.org") || strings.Contains(errb, "d.org") {
		t.Errorf("only the build's fetchers are listed:\n%s", errb)
	}
}

func TestLintScriptFetchesRefusesARegression(t *testing.T) {
	rc, _, errb := lint(t, "--dir", fetchTree(t), "--max-script-fetches", "1")
	if rc != 1 || !strings.Contains(errb, "2 of 4 recipe(s) fetch a remote artifact") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

func TestLintScriptFetchesRefusesAStaleCeiling(t *testing.T) {
	rc, _, errb := lint(t, "--dir", fetchTree(t), "--max-script-fetches", "3")
	if rc != 1 || !strings.Contains(errb, "lower it to 2") {
		t.Fatalf("rc=%d\n%s", rc, errb)
	}
}

// Naming the check without a number is the strict reading: zero tolerated.
func TestLintScriptFetchesZeroIsTheDefaultAndNotUnset(t *testing.T) {
	if rc, _, _ := lint(t, "--dir", fetchTree(t), "--require-pinned-fetches"); rc != 1 {
		t.Error("a fetching recipe must fail with no ceiling")
	}
	clean := lintTree(t, map[string]string{
		"d.org/package.hcl": "versions { github = \"c/c\" }\n" +
			"distributable { url = \"https://c.org/{{version}}.tar.gz\" }\n" +
			"build { script = \"make install\" }\n",
	})
	for _, args := range [][]string{{"--require-pinned-fetches"}, {"--max-script-fetches", "0"}} {
		if rc, out, errb := lint(t, append([]string{"--dir", clean}, args...)...); rc != 0 || !strings.Contains(out, "script fetches: 0 recipe(s)") {
			t.Errorf("%v: rc=%d %s\n%s", args, rc, out, errb)
		}
	}
	// and without either flag the check is off, so the tree reads clean
	if rc, out, _ := lint(t, "--dir", fetchTree(t)); rc != 0 || strings.Contains(out, "script fetches") {
		t.Errorf("off by default: rc=%d %s", rc, out)
	}
}
