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

func writeTree(t *testing.T, root string) {
	t.Helper()
	for p, c := range map[string]string{"bin/tool": "#!/bin/sh\n", "share/doc": "docs"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if p == "bin/tool" {
			mode = 0o755
		}
		if err := os.WriteFile(full, []byte(c), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("tool", filepath.Join(root, "bin", "alias")); err != nil {
		t.Fatal(err)
	}
}

func TestSameTreeComparesBytesNotNames(t *testing.T) {
	ref, got := t.TempDir(), t.TempDir()
	writeTree(t, ref)
	writeTree(t, got)
	if err := sameTree(ref, got); err != nil {
		t.Fatalf("identical trees: %v", err)
	}
	// The installer's own marker is the one thing allowed to be extra.
	if err := os.WriteFile(filepath.Join(got, artifact.SeedMarkerName), []byte("sha256:x\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := sameTree(ref, got); err != nil {
		t.Fatalf("the seed marker must be allowed: %v", err)
	}

	mutate := map[string]func(){
		"changed content": func() { os.WriteFile(filepath.Join(got, "share", "doc"), []byte("docX"), 0o644) },
		"changed mode":    func() { os.Chmod(filepath.Join(got, "bin", "tool"), 0o700) },
		"setuid added":    func() { os.Chmod(filepath.Join(got, "bin", "tool"), 0o755|os.ModeSetuid) },
		"setgid added":    func() { os.Chmod(filepath.Join(got, "bin", "tool"), 0o755|os.ModeSetgid) },
		"sticky dir":      func() { os.Chmod(filepath.Join(got, "share"), 0o755|os.ModeSticky) },
		"directory mode":  func() { os.Chmod(filepath.Join(got, "share"), 0o700) },
		"extra file":      func() { os.WriteFile(filepath.Join(got, "bin", "extra"), nil, 0o644) },
		"missing file":    func() { os.Remove(filepath.Join(got, "share", "doc")) },
		"retargeted link": func() {
			os.Remove(filepath.Join(got, "bin", "alias"))
			os.Symlink("elsewhere", filepath.Join(got, "bin", "alias"))
		},
		"link for file": func() {
			os.Remove(filepath.Join(got, "share", "doc"))
			os.Symlink("../bin/tool", filepath.Join(got, "share", "doc"))
		},
	}
	for name, f := range mutate {
		g := t.TempDir()
		writeTree(t, g)
		got = g
		f()
		if err := sameTree(ref, g); err == nil {
			t.Errorf("%s: not refused", name)
		}
	}
}

func TestOriginSeededRootRefusesBytesThatDifferFromTheSignedArtifact(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	root := t.TempDir()
	mkVersions(t, root, "a.org/v1.0", "b.org/v2.0")
	stubVerifiedBy(t, nil)
	installedBytes = func(_ string, tg seedTarget, _, _, _ string) error {
		if tg.project == "b.org" {
			return errors.New("bin/x differs from the artifact's")
		}
		return nil
	}
	var out, errOut bytes.Buffer
	code := runOrigin([]string{"--platform", "linux/s390x", "--dist", "oci://x/y", "--seeded", "--root", root}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "b.org 2.0") || strings.Contains(errOut.String(), "a.org") {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
}
