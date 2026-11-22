package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-zpkg/artifact"
)

type fakeReader struct{ failAt string }

func (f fakeReader) ArtifactDigest(_, _, _, _ string) (string, error) {
	if f.failAt == "digest" {
		return "", errors.New("digest down")
	}
	return testDigest, nil
}

func (f fakeReader) VerifiedPayloads(_, _, _, _, d string) ([][]byte, error) {
	if f.failAt == "payloads" {
		return nil, errors.New("not signed by a trusted key")
	}
	if d != testDigest {
		return nil, errors.New("payloads asked for another digest")
	}
	return [][]byte{[]byte("p")}, nil
}

func (f fakeReader) FetchAttestations(_, _, _, _ string) ([]artifact.Referrer, map[string]string, error) {
	if f.failAt == "referrers" {
		return nil, nil, errors.New("referrers down")
	}
	return nil, nil, nil
}

// TestEveryRegistryReadIsAnError: a failed read at any of the three steps is an
// error and never a partial answer, and the payloads are asked for the digest
// the first read returned.
func TestEveryRegistryReadIsAnError(t *testing.T) {
	for _, at := range []string{"digest", "payloads", "referrers"} {
		if _, _, _, err := readVerified(fakeReader{failAt: at}, "p", "t", "linux", "s390x"); err == nil {
			t.Errorf("a failure at %s was swallowed", at)
		}
	}
	d, p, _, err := readVerified(fakeReader{}, "p", "t", "linux", "s390x")
	if err != nil || d != testDigest || len(p) != 1 {
		t.Errorf("d=%q p=%d err=%v", d, len(p), err)
	}
}

// TestAnUnreadableStubIsNotAStub: a compiler that cannot be read cannot be
// shown to be one of our stubs.
func TestAnUnreadableStubIsNotAStub(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	writeFile(t, root, "usr/bin/cc", stubPrefix+"\"/x\"\n")
	if err := os.Chmod(filepath.Join(root, "usr/bin/cc"), 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := sovereignClaim("zpkx", false, root); got != "0" {
		t.Error("an unreadable compiler passed as a stub")
	}
}
