package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

func mkVersions(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, r := range rels {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(r), "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSeedTargetsListsEveryProjectVersion(t *testing.T) {
	root := t.TempDir()
	// Project names carry slashes; v8.dev looks like a version and is a project.
	mkVersions(t, root, "gnu.org/make/v4.4.1", "go.dev/v1.23.0", "go.dev/v1.22.0", "v8.dev/v12.0", "g.org/v8.dev/v12.0")
	if err := os.MkdirAll(filepath.Join(root, "empty.org"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "v1.stray"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := seedTargets(root + string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range got {
		names = append(names, g.project+"@"+g.version)
	}
	want := "g.org/v8.dev@12.0 gnu.org/make@4.4.1 go.dev@1.22.0 go.dev@1.23.0 v8.dev@12.0"
	if strings.Join(names, " ") != want {
		t.Fatalf("got %v, want %s", names, want)
	}
}

func TestSeedTargetsRefusesAnEmptyOrMissingRoot(t *testing.T) {
	empty := t.TempDir()
	if _, err := seedTargets(empty); err == nil || !strings.Contains(err.Error(), "nothing to verify") {
		t.Errorf("an empty root: %v", err)
	}
	// A project directory with no version below it, and a v<digit> directory
	// directly under the root, are not installs either.
	mkVersions(t, empty)
	if err := os.MkdirAll(filepath.Join(empty, "v9.dev", "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := seedTargets(empty); err == nil || !strings.Contains(err.Error(), "nothing to verify") {
		t.Errorf("no version below a project: %v", err)
	}
	if _, err := seedTargets(filepath.Join(empty, "absent")); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Errorf("a missing root: %v", err)
	}
}

// stubVerifiedBy answers each project from its own error.
func stubVerifiedBy(t *testing.T, fails map[string]error) *[]string {
	t.Helper()
	o := seededOrigin()
	d, p, r := signedFixture(t, o)
	old, oldBytes := sourceVerified, installedBytes
	t.Cleanup(func() { sourceVerified, installedBytes = old, oldBytes })
	installedBytes = func(_ string, _ seedTarget, _, _, digest string) error {
		if digest != d {
			return errors.New("bytes compared against the wrong digest")
		}
		return nil
	}
	var asked []string
	sourceVerified = func(_, project, version, _, _ string) (string, [][]byte, []artifact.Referrer, error) {
		asked = append(asked, project+"@"+version)
		if err := fails[project]; err != nil {
			return "", nil, nil, err
		}
		return d, p, r, nil
	}
	return &asked
}

func TestOriginSeededRootChecksEveryArtifactAndFailsOnAnyOne(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	root := t.TempDir()
	mkVersions(t, root, "a.org/v1.0", "b.org/v2.0", "c.org/v3.0")
	args := func(extra ...string) []string {
		return append([]string{"--platform", "linux/s390x", "--dist", "oci://x/y", "--seeded", "--root", root}, extra...)
	}

	asked := stubVerifiedBy(t, nil)
	var out, errOut bytes.Buffer
	if code := runOrigin(args(), &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("every artifact seeded: %d out=%q err=%q", code, out.String(), errOut.String())
	}
	if len(*asked) < 3 {
		t.Fatalf("not every artifact was asked about: %v", *asked)
	}

	// One refusal fails the whole, and both bad ones are named.
	stubVerifiedBy(t, map[string]error{"a.org": errors.New("registry down"), "c.org": errors.New("registry down")})
	errOut.Reset()
	code := runOrigin(args(), &out, &errOut)
	msg := errOut.String()
	if code != 1 || !strings.Contains(msg, "2 of 3") || !strings.Contains(msg, "a.org 1.0") || !strings.Contains(msg, "c.org 3.0") || strings.Contains(msg, "b.org") {
		t.Errorf("a failing artifact: %d %q", code, msg)
	}

	// The ledger digest applies to every artifact.
	stubVerifiedBy(t, nil)
	errOut.Reset()
	if code := runOrigin(args("--seed-ledger-sha256", strings.Repeat("1", 64)), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "3 of 3") {
		t.Errorf("another ledger: %d %q", code, errOut.String())
	}
}

func TestOriginSeededRootRefusesAnEmptyRootAndItsContradictions(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerifiedBy(t, nil)
	var out, errOut bytes.Buffer
	if code := runOrigin([]string{"--platform", "linux/s390x", "--dist", "oci://x/y", "--seeded", "--root", t.TempDir()}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "nothing to verify") {
		t.Errorf("an empty root: %d %q", code, errOut.String())
	}
	for _, args := range [][]string{
		{"--root", t.TempDir()},
		{"--seeded", "--root", t.TempDir(), "acme.org/tool", "1.2.3"},
		{"--promotable", "--seeded", "--root", t.TempDir()},
	} {
		errOut.Reset()
		if code := runOrigin(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, %q", args, code, errOut.String())
		}
	}
}
