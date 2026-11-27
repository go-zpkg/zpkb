package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// ⛔ UNDER A SEED THE FACTORY, NOT THE TEST SCRIPT, INSTALLS THE TEST CLOSURE.
// The script ran `zpkx +gnu.org/gcc +llvm.org …` with $ZPKX_SEEDED inherited,
// and zpkx refused ("a seed is in force … would be fetched from outside it"):
// ~15 packages ended NOT-RUN and no staged artifact was tested. The factory's
// provisioner (the one the build used, which records the ledger) gets the specs
// and the script evaluates what it returns, calling no zpkx for packages.
func TestSeededTestEnvironmentIsProvisionedByTheFactoryNotByZpkx(t *testing.T) {
	const recipe = "versions:\n  - 1.2.3\ndependencies:\n  dep.org: ^2\nbuild: make\ntest: true\n"
	var out bytes.Buffer
	rec, dir := parseRecipe(t, recipe)
	f := testFactory(t, &out, dir)
	var asked []string
	f.runner.Provision = func(specs []string) (string, error) {
		asked = append(asked, specs...)
		return "PROVISIONED_MARK=1", nil
	}
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

	if got := f.runPublishedTest(rec, "proj.org", "1.2.3", "", true); got != testPassed {
		t.Fatalf("state %q:\n%s", got, out.String())
	}
	if !strings.Contains(strings.Join(asked, " "), "dep.org") {
		t.Errorf("the provisioner was asked for %v, want the runtime dependency dep.org", asked)
	}
	if !strings.Contains(script, "PROVISIONED_MARK=1") {
		t.Errorf("the script does not evaluate the provisioned environment:\n%s", script)
	}
	if strings.Contains(script, `"+dep.org`) {
		t.Errorf("the script still asks zpkx for packages, which a seed refuses:\n%s", script)
	}
}

// A provisioner that refuses (an outside fetch under a seed) keeps the test
// NOT-RUN: the refusal is correct and must stay, and is never a PASS.
func TestSeededTestEnvironmentRefusalStaysNotRun(t *testing.T) {
	const recipe = "versions:\n  - 1.2.3\nbuild: make\ntest: true\n"
	var out bytes.Buffer
	rec, dir := parseRecipe(t, recipe)
	f := testFactory(t, &out, dir)
	f.runner.Provision = func([]string) (string, error) { return "", io.ErrUnexpectedEOF }
	prev := factoryTestRunner
	factoryTestRunner = func(time.Duration, io.Writer, io.Writer) func(string, []string) error {
		return func(string, []string) error { t.Fatal("the test ran despite a refused environment"); return nil }
	}
	t.Cleanup(func() { factoryTestRunner = prev })
	if got := f.runPublishedTest(rec, "proj.org", "1.2.3", "", true); got != testNotRun {
		t.Fatalf("state %q, want NOT-RUN:\n%s", got, out.String())
	}
}
