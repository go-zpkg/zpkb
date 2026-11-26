package main

import (
	"archive/tar"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-zpkg/artifact"
)

// bytesSource is where the signed artifact's bytes come from.
type bytesSource interface {
	ArtifactDigest(project, ver, osn, arch string) (string, error)
	Pull(project, ver, osn, arch string) (io.ReadCloser, string, error)
}

// ociBytes is the registry as a bytesSource.
type ociBytes struct{ c *artifact.OCIClient }

func (o ociBytes) ArtifactDigest(project, ver, osn, arch string) (string, error) {
	return o.c.ArtifactDigest(project, ver, osn, arch)
}

// pulledBlob is a staged blob that closes itself and is only used on success.
type pulledBlob struct{ *artifact.BlobFile }

func (o ociBytes) Pull(project, ver, osn, arch string) (io.ReadCloser, string, error) {
	f, ext, err := o.c.PullFile(project, ver, osn, arch)
	return pulledBlob{f}, ext, err
}

// installedBytes says the files under t.path are the files of the artifact whose
// digest the signature vouches for. A seam: the real one reads the registry.
var installedBytes = func(dist string, t seedTarget, osn, arch, digest string) error {
	c, err := artifact.NewOCIClient(dist)
	if err != nil {
		return err
	}
	// The signature was read under the tag the registry holds the version by
	// (`1.0-h<hash>`), so the bytes are read under the same one: a bare
	// directory name must not ask for a tag the registry does not have.
	if t.version, err = resolveBuildTag(c, t.project, t.version, osn, arch); err != nil {
		return err
	}
	return compareInstalled(ociBytes{c}, t, osn, arch, digest)
}

// compareInstalled pulls the artifact, unpacks it the way the installer does and
// requires the installed tree to be the same.
func compareInstalled(src bytesSource, t seedTarget, osn, arch, digest string) error {
	got, err := src.ArtifactDigest(t.project, t.version, osn, arch)
	if err != nil {
		return fmt.Errorf("cannot read the artifact digest to compare the installed bytes: %w", err)
	}
	if got != digest {
		return fmt.Errorf("the registry now serves digest %s, the signature vouches for %s", got, digest)
	}
	f, ext, err := src.Pull(t.project, t.version, osn, arch)
	if err != nil {
		return fmt.Errorf("cannot pull the artifact to compare the installed bytes: %w", err)
	}
	defer f.Close()
	return unpackAndCompare(f, ext, t.path)
}

func unpackAndCompare(body io.Reader, ext, installed string) error {
	r, closeDec, err := artifact.Decompressor(ext, body)
	if err != nil {
		return err
	}
	defer closeDec()
	ref, err := os.MkdirTemp("", "zpkb-seedbytes-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(ref)
	if err := artifact.Extract(tar.NewReader(r), ref, 0); err != nil {
		return fmt.Errorf("cannot unpack the artifact to compare the installed bytes: %w", err)
	}
	return sameTree(ref, installed)
}

// walkRel calls fn with the path relative to root of every entry under it.
func walkRel(root string, fn func(rel string) error) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p) // p is under root: cannot fail
		return fn(rel)
	})
}

// sameTree requires installed to hold exactly the entries of ref: same kinds,
// same permission bits, same file contents, same link targets. The one file the
// installer adds on its own, the seed marker, is allowed at the top.
// Modification times are not content and are not compared.
func sameTree(ref, installed string) error {
	seen := map[string]bool{}
	err := walkRel(ref, func(rel string) error {
		seen[rel] = true
		return sameEntry(filepath.Join(ref, rel), filepath.Join(installed, rel), rel)
	})
	if err != nil {
		return err
	}
	return walkRel(installed, func(rel string) error {
		if !seen[rel] && rel != artifact.SeedMarkerName {
			return fmt.Errorf("%s is installed but not in the artifact", rel)
		}
		return nil
	})
}

// fileSum is the content hash of a file; a seam so a read failure is testable
// without depending on file permissions.
var fileSum = fileDigest

func sameEntry(want, have, rel string) error {
	ws, err := os.Lstat(want)
	if err != nil {
		return err
	}
	hs, err := os.Lstat(have)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is in the artifact but not installed", rel)
	}
	if err != nil {
		return err
	}
	if ws.Mode().Type() != hs.Mode().Type() {
		return fmt.Errorf("%s is a %v in the artifact and a %v installed", rel, ws.Mode().Type(), hs.Mode().Type())
	}
	switch {
	case ws.Mode()&fs.ModeSymlink != 0:
		wl, _ := os.Readlink(want) // Lstat said it is a link
		hl, _ := os.Readlink(have)
		if wl != hl {
			return fmt.Errorf("%s is a link to %q in the artifact and to %q installed", rel, wl, hl)
		}
	case ws.Mode().IsRegular():
		if ws.Mode().Perm() != hs.Mode().Perm() {
			return fmt.Errorf("%s has mode %v in the artifact and %v installed", rel, ws.Mode().Perm(), hs.Mode().Perm())
		}
		wd, werr := fileSum(want)
		hd, herr := fileSum(have)
		if err := errors.Join(werr, herr); err != nil {
			return err
		}
		if wd != hd {
			return fmt.Errorf("%s differs from the artifact's", rel)
		}
	}
	return nil
}

func fileDigest(p string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(p)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
