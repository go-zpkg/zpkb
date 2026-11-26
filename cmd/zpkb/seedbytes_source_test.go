package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// tarballOf packs the tree under root the way an artifact is packed.
func tarballOf(t *testing.T, root string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := walkRel(root, func(rel string) error {
		if rel == "." {
			return nil
		}
		p := filepath.Join(root, rel)
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		link := ""
		if st.Mode()&os.ModeSymlink != 0 {
			link, _ = os.Readlink(p)
		}
		h, err := tar.FileInfoHeader(st, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if st.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			_, err = tw.Write(b)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type fakeBytes struct {
	digest  string
	digErr  error
	pullErr error
	body    []byte
	ext     string
}

func (f fakeBytes) ArtifactDigest(_, _, _, _ string) (string, error) { return f.digest, f.digErr }
func (f fakeBytes) Pull(_, _, _, _ string) (io.ReadCloser, string, error) {
	if f.pullErr != nil {
		return nil, "", f.pullErr
	}
	return io.NopCloser(bytes.NewReader(f.body)), f.ext, nil
}

func TestCompareInstalledReadsTheSignedArtifactAndComparesItsBytes(t *testing.T) {
	ref, got := t.TempDir(), t.TempDir()
	writeTree(t, ref)
	writeTree(t, got)
	body := tarballOf(t, ref)
	tg := seedTarget{path: got, project: "a.org", version: "1.0"}
	ok := fakeBytes{digest: "sha256:d", body: body, ext: artifact.ExtTarGz}

	if err := compareInstalled(ok, tg, "linux", "x86-64", "sha256:d"); err != nil {
		t.Fatalf("matching bytes: %v", err)
	}
	if err := compareInstalled(ok, tg, "linux", "x86-64", "sha256:other"); err == nil || !strings.Contains(err.Error(), "now serves") {
		t.Errorf("a registry serving another digest: %v", err)
	}
	boom := errors.New("boom")
	bad := ok
	bad.digErr = boom
	if err := compareInstalled(bad, tg, "linux", "x86-64", "sha256:d"); !errors.Is(err, boom) {
		t.Errorf("digest failure: %v", err)
	}
	bad = ok
	bad.pullErr = boom
	if err := compareInstalled(bad, tg, "linux", "x86-64", "sha256:d"); !errors.Is(err, boom) {
		t.Errorf("pull failure: %v", err)
	}
	// The installed prefix was changed after the install: refused.
	if err := os.WriteFile(filepath.Join(got, "share", "doc"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := compareInstalled(ok, tg, "linux", "x86-64", "sha256:d"); err == nil || !strings.Contains(err.Error(), "share/doc") {
		t.Errorf("tampered bytes: %v", err)
	}
}

func TestUnpackAndCompareRefusals(t *testing.T) {
	if err := unpackAndCompare(strings.NewReader("x"), ".bogus", t.TempDir()); err == nil {
		t.Error("an unknown codec must be refused")
	}
	if err := unpackAndCompare(strings.NewReader("not gzip"), artifact.ExtTarGz, t.TempDir()); err == nil {
		t.Error("garbage must be refused")
	}
	var junk bytes.Buffer
	jz := gzip.NewWriter(&junk)
	jz.Write(bytes.Repeat([]byte("not a tar header "), 100))
	jz.Close()
	if err := unpackAndCompare(&junk, artifact.ExtTarGz, t.TempDir()); err == nil || !strings.Contains(err.Error(), "cannot unpack") {
		t.Errorf("a stream that is not a tar: %v", err)
	}
	var empty bytes.Buffer
	gz := gzip.NewWriter(&empty)
	tar.NewWriter(gz).Close()
	gz.Close()
	bad := empty.Bytes()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("TMP", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("TEMP", filepath.Join(t.TempDir(), "absent"))
	if err := unpackAndCompare(bytes.NewReader(bad), artifact.ExtTarGz, t.TempDir()); err == nil {
		t.Error("no scratch directory must be refused")
	}
}

func TestSameEntryAndWalkFailuresAreErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sameEntry(filepath.Join(dir, "absent"), file, "r"); err == nil {
		t.Error("missing reference entry")
	}
	if err := sameEntry(file, filepath.Join(file, "below"), "r"); err == nil || strings.Contains(err.Error(), "not installed") {
		t.Errorf("an unreadable installed path is not 'not installed': %v", err)
	}
	if err := walkRel(filepath.Join(dir, "absent"), func(string) error { return nil }); err == nil {
		t.Error("walking a missing root")
	}
	if err := sameTree(dir, filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing install")
	}
	// A directory installed under a name that is a file in the artifact differs by kind.
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "f"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sameEntry(file, filepath.Join(other, "f"), "f"); err == nil {
		t.Error("kind mismatch")
	}
	// A file that cannot be hashed fails the comparison.
	old := fileSum
	t.Cleanup(func() { fileSum = old })
	fileSum = func(string) ([32]byte, error) { return [32]byte{}, errors.New("unreadable") }
	if err := sameEntry(file, file, "f"); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("hash failure: %v", err)
	}
	if _, err := fileDigest(filepath.Join(dir, "absent")); err == nil {
		t.Error("fileDigest of a missing file")
	}
	if _, err := fileDigest(dir); err == nil {
		t.Error("fileDigest of a directory")
	}
}

func TestInstalledBytesFailsOnAnUnreachableRegistry(t *testing.T) {
	err := installedBytes("oci://127.0.0.1:1/seed", seedTarget{path: t.TempDir(), project: "lz4.org", version: "1.10.0"}, "linux", "s390x", "sha256:d")
	if err == nil {
		t.Fatal("an unreachable registry was read")
	}
	if err := installedBytes("", seedTarget{}, "linux", "s390x", "sha256:d"); err == nil {
		t.Fatal("no registry was accepted")
	}
	c, _ := artifact.NewOCIClient("oci://127.0.0.1:1/seed")
	if _, _, err := (ociBytes{c}).Pull("lz4.org", "1.10.0", "linux", "s390x"); err == nil {
		t.Fatal("an unreachable registry was pulled")
	}
}
