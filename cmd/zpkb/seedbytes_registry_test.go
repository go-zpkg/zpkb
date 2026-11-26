//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// The installed bytes are compared against a REAL registry here: an in-process
// OCI registry that the real `publish` pushed to, read back through the real
// OCI client (ArtifactDigest, PullFile) under the `-h<hash>` tag an install
// directory carries.
func TestInstalledBytesAgainstARegistryUnderTheBuildTag(t *testing.T) {
	m := newMiniOCI()
	defer m.close()

	ref := t.TempDir()
	writeTree(t, ref)
	tarball := filepath.Join(t.TempDir(), "seedx.tar.gz")
	if err := os.WriteFile(tarball, tarballOf(t, ref), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run2(t, "publish", "--to", m.base(), "--project", "example.org/seedx",
		"--version", "1.0", "--platform", "linux/x86-64",
		"--spec-recipe", "sha256:abc", "--allow-unsigned", tarball)
	if code != 0 {
		t.Fatalf("publish code=%d err=%q", code, errs)
	}
	tag := ""
	for _, g := range m.tags {
		if strings.HasPrefix(g, "1.0-h") {
			tag = g
		}
	}
	if tag == "" {
		t.Fatalf("publish pushed no build tag (%v): %q", m.tags, out)
	}

	c, err := artifact.NewOCIClient(m.base())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := c.ArtifactDigest("example.org/seedx", tag, "linux", "x86-64")
	if err != nil {
		t.Fatalf("ArtifactDigest(%s): %v", tag, err)
	}

	installed := t.TempDir()
	writeTree(t, installed)
	tg := seedTarget{path: installed, project: "example.org/seedx", version: tag}
	if err := installedBytes(m.base(), tg, "linux", "x86-64", digest); err != nil {
		t.Fatalf("the installed bytes of %s against the registry: %v", tag, err)
	}
	// A bare version resolves to the build tag the registry holds it by.
	bare := seedTarget{path: installed, project: "example.org/seedx", version: "1.0"}
	if err := installedBytes(m.base(), bare, "linux", "x86-64", digest); err != nil {
		t.Fatalf("the bare version 1.0 against the registry: %v", err)
	}
	// A tag the registry cannot list is an error, not a silent fall-through.
	gone := seedTarget{path: installed, project: "example.org/absent", version: "1.0"}
	if err := installedBytes(m.base(), gone, "linux", "x86-64", digest); err == nil || !strings.Contains(err.Error(), "tags/list") {
		t.Errorf("an unlistable project: %v", err)
	}
	// A different signed digest is refused.
	if err := installedBytes(m.base(), tg, "linux", "x86-64", "sha256:00"); err == nil || !strings.Contains(err.Error(), "now serves") {
		t.Errorf("another digest: %v", err)
	}
	// A tampered install is refused.
	if err := os.WriteFile(filepath.Join(installed, "share", "doc"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installedBytes(m.base(), tg, "linux", "x86-64", digest); err == nil || !strings.Contains(err.Error(), "share/doc") {
		t.Errorf("tampered install: %v", err)
	}
}
