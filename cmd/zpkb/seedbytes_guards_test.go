package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// Each refusal below is asserted by the words it carries, so a guard that is
// deleted turns into a different message, not into the same failure by luck.

func TestSeedBytesRefusalsSayWhichStepFailed(t *testing.T) {
	boom := errors.New("boom")
	tg := seedTarget{path: t.TempDir(), project: "a.org", version: "1.0"}
	if err := compareInstalled(fakeBytes{digErr: boom}, tg, "linux", "x86-64", "sha256:d"); err == nil || !strings.Contains(err.Error(), "cannot read the artifact digest") {
		t.Errorf("digest failure: %v", err)
	}
	if err := compareInstalled(fakeBytes{digest: "sha256:d", pullErr: boom}, tg, "linux", "x86-64", "sha256:d"); err == nil || !strings.Contains(err.Error(), "cannot pull the artifact") {
		t.Errorf("pull failure: %v", err)
	}
	if err := unpackAndCompare(strings.NewReader("x"), ".bogus", t.TempDir()); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("an unknown codec is named: %v", err)
	}
}

func TestSeedBytesScratchDirectoryFailureIsNamed(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	t.Setenv("TMPDIR", absent)
	t.Setenv("TMP", absent)
	t.Setenv("TEMP", absent)
	body := tarballOf(t, t.TempDir())
	err := unpackAndCompare(strings.NewReader(string(body)), artifact.ExtTarGz, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), absent) {
		t.Errorf("the scratch directory failure: %v", err)
	}
}

func TestSeedBytesInstalledClientFailureIsTheClientsOwn(t *testing.T) {
	_, want := artifact.NewOCIClient("")
	if want == nil {
		t.Skip("an empty registry is accepted by this client")
	}
	err := installedBytes("", seedTarget{}, "linux", "s390x", "sha256:d")
	if err == nil || err.Error() != want.Error() {
		t.Errorf("got %v, want %v", err, want)
	}
}

func TestSameEntryNamesTheKindOfDifference(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := sameEntry(file, filepath.Join(other, "gone"), "gone"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("a missing installed entry: %v", err)
	}
	if err := os.Mkdir(filepath.Join(other, "f"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sameEntry(file, filepath.Join(other, "f"), "f"); err == nil || !strings.Contains(err.Error(), "in the artifact and a") {
		t.Errorf("a directory where the artifact has a file: %v", err)
	}
	if err := sameEntry(filepath.Join(dir, "absent"), file, "r"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing reference entry keeps its cause: %v", err)
	}
	if _, err := fileDigest(filepath.Join(dir, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("fileDigest of a missing file keeps its cause: %v", err)
	}
}
