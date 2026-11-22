package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/zpkb/buildscript"
	"mvdan.cc/sh/v3/interp"
)

// ⛔ UNDER --stage-only THE PACKAGE UNDER TEST IS NOT IN ANY REGISTRY. The test
// environment ran `zpkx +lz4.org@1.11.1 …`, which resolves from ZPKG_DIST, and
// ended "no version of lz4.org satisfies 1.11.1" — NOT-RUN, with nothing tested
// (smoke run 45076704819). The staged package is taken from its installed
// prefix instead, and the environment keeps the artifact's runtime dependencies.
func TestStagedTestDoesNotAskTheRegistryForThePackageUnderTest(t *testing.T) {
	const recipe = "versions:\n  - 1.2.3\ndependencies:\n  dep.org: ^2\nbuild: make\ntest: true\n"
	for _, tc := range []struct {
		name   string
		staged bool
	}{{"published", false}, {"staged", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			rec, dir := parseRecipe(t, recipe)
			f := testFactory(t, &out, dir)
			var script string
			prev := factoryTestRunner
			factoryTestRunner = func(time.Duration, io.Writer, io.Writer) func(string, []string) error {
				return func(path string, _ []string) error {
					b, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					script = string(b)
					return nil
				}
			}
			t.Cleanup(func() { factoryTestRunner = prev })

			if got := f.runPublishedTest(rec, "proj.org", "1.2.3", "", tc.staged); got != testPassed {
				t.Fatalf("state %q:\n%s", got, out.String())
			}
			asksForPackage := strings.Contains(script, `"+proj.org@`)
			if asksForPackage == tc.staged {
				t.Errorf("staged=%v but the environment asks the registry for the package under test = %v:\n%s",
					tc.staged, asksForPackage, script)
			}
			// The package's own spec pulls its runtime closure in when it is asked
			// of the registry; without it they have to be named, or the staged
			// package would be tested with its libraries missing.
			if hasDep := strings.Contains(script, `"+dep.org`); hasDep != tc.staged {
				t.Errorf("runtime dependency named in the environment = %v, want %v (staged=%v):\n%s", hasDep, tc.staged, tc.staged, script)
			}
			// Either way the build's own bin is put on PATH: that is what runs.
			if !strings.Contains(script, "/bin:") {
				t.Errorf("the package's prefix is not on PATH (staged=%v):\n%s", tc.staged, script)
			}
		})
	}
}

// stageVerdictRig stages app.org and lib.org with a test block each and the
// given outcome for the test run, then returns the rig and the stage's output.
func stageVerdictRig(t *testing.T, recipeTest string, outcome func(scriptPath string) error, stageArgs ...string) *stageRig {
	t.Helper()
	r := newStageRig(t)
	writeClosureRecipe(t, r.h.pantry, "lib.org", "versions:\n  - 9.9\nbuild: make\n"+recipeTest)
	writeClosureRecipe(t, r.h.pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  - 2.0\nbuild: make\n"+recipeTest)
	prev := factoryTestRunner
	factoryTestRunner = func(time.Duration, io.Writer, io.Writer) func(string, []string) error {
		return func(path string, _ []string) error { return outcome(path) }
	}
	t.Cleanup(func() { factoryTestRunner = prev })
	args := append([]string{"--stage-only", "--recipes", "app.org", "--max-versions", "1", "--to", stageDist}, stageArgs...)
	if code := r.h.run(t, args...); code != 0 {
		t.Fatalf("stage-only: code=%d\n%s\n%s", code, r.h.out.String(), r.h.errb.String())
	}
	return r
}

func planVerdicts(t *testing.T, r *stageRig) map[string]string {
	t.Helper()
	b, err := os.ReadFile(r.h.artifacts + "/" + stagePlanName)
	if err != nil {
		t.Fatal(err)
	}
	var plan stagePlan
	if err := json.Unmarshal(b, &plan); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range plan.Artifacts {
		got[e.Project] = e.Test
	}
	return got
}

// The verdict is written into publish-plan.json, and publish-stage refuses what
// the verdict says it must: it signed and pushed a NOT-RUN artifact before.
func TestPublishStageRefusesAnArtifactWhoseTestDidNotPass(t *testing.T) {
	pass := func(string) error { return nil }
	fail := func(string) error { return interp.ExitStatus(1) }
	notRun := func(string) error { return interp.ExitStatus(buildscript.EnvFailExit) }
	libFails := func(p string) error {
		if strings.Contains(p, "lib.org") {
			return interp.ExitStatus(1)
		}
		return nil
	}
	const withTest = "test: true\n"
	for _, tc := range []struct {
		name       string
		recipeTest string
		outcome    func(string) error
		args       []string
		verdicts   map[string]string
		published  string // "N published, M failed" as publish-stage prints it
		wantCode   int
		wantStderr string
	}{
		{"pass", withTest, pass, nil, map[string]string{"app.org": "pass", "lib.org": "pass"}, "2 published, 0 failed", 0, ""},
		{"fail", withTest, fail, nil, map[string]string{"app.org": "fail", "lib.org": "fail"}, "0 published, 2 failed", 1, "its own test FAILED"},
		{"not-run", withTest, notRun, nil, map[string]string{"app.org": "not-run", "lib.org": "not-run"}, "0 published, 2 failed", 1, "did NOT RUN"},
		// A recipe with no test block is its own explicit state, and the policy
		// is the one `factory` always had: it is published, and said so.
		{"no test block", "", pass, nil, map[string]string{"app.org": "no-test", "lib.org": "no-test"}, "2 published, 0 failed", 0, ""},
		// Testing switched off by the operator is explicit too, and publishes.
		{"tests switched off", withTest, fail, []string{"--test=false"}, map[string]string{"app.org": "skipped", "lib.org": "skipped"}, "2 published, 0 failed", 0, ""},
		// One bad artifact is refused alone; the others still go.
		{"one of two fails", withTest, libFails, nil, map[string]string{"app.org": "pass", "lib.org": "fail"}, "1 published, 1 failed", 1, "lib.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := stageVerdictRig(t, tc.recipeTest, tc.outcome, tc.args...)
			got := planVerdicts(t, r)
			for p, want := range tc.verdicts {
				if got[p] != want {
					t.Errorf("plan verdict of %s = %q, want %q (all: %v)\n%s\n%s", p, got[p], want, got, r.h.out.String(), r.h.errb.String())
				}
			}
			code, out, errb := r.publishStage("--to", stageDist, "--sign", r.key)
			if code != tc.wantCode {
				t.Errorf("publish-stage code %d, want %d\n%s\n%s", code, tc.wantCode, out, errb)
			}
			if !strings.Contains(out, tc.published) {
				t.Errorf("want %q in:\n%s\n%s", tc.published, out, errb)
			}
			if tc.wantStderr != "" && !strings.Contains(errb, tc.wantStderr) {
				t.Errorf("want %q in stderr:\n%s", tc.wantStderr, errb)
			}
			if tc.wantCode == 1 && tc.published == "0 published, 2 failed" && len(r.pushes) != 0 {
				t.Errorf("a refused artifact was pushed: %v", r.pushes)
			}
		})
	}
}

// A plan with no verdict at all (an older zpkb, or a build that never recorded
// one) is refused: an absent answer is not a green one.
func TestPublishStageRefusesAPlanWithNoTestVerdict(t *testing.T) {
	r := stageVerdictRig(t, "test: true\n", func(string) error { return nil })
	path := r.h.artifacts + "/" + stagePlanName
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan stagePlan
	if err := json.Unmarshal(b, &plan); err != nil {
		t.Fatal(err)
	}
	for i := range plan.Artifacts {
		plan.Artifacts[i].Test = ""
	}
	b, _ = json.Marshal(plan)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := r.publishStage("--to", stageDist, "--sign", r.key)
	if code != 1 || !strings.Contains(out, "0 published, 2 failed") || !strings.Contains(errb, "records no test verdict") {
		t.Errorf("code %d\n%s\n%s", code, out, errb)
	}
	if len(r.pushes) != 0 {
		t.Errorf("pushed without a verdict: %v", r.pushes)
	}
}

// The policy as a table, so that every verdict has a stated outcome and an
// unknown one cannot slip through as "fine".
func TestStageTestRefusal(t *testing.T) {
	for verdict, refused := range map[string]bool{
		"pass": false, "no-test": false, "skipped": false,
		"fail": true, "not-run": true, "": true, "PASS": true, "passed": true, "anything": true,
	} {
		why := stageTestRefusal(stageEntry{Test: verdict})
		if (why != "") != refused {
			t.Errorf("verdict %q: refusal %q, want refused=%v", verdict, why, refused)
		}
	}
}
