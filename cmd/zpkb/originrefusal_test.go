package main

import (
	"bytes"
	"strings"
	"testing"
)

// A promotion whose source cannot carry signatures is refused by BOTH entry
// points, with the reason, and without ever reading the registry.
func TestPromotableRefusedWithoutAnOCISource(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "1")
	stubVerified(t, sovereignSource, nil)

	var out, errOut bytes.Buffer
	if code := runOrigin(originArgs("--dist", "https://static.example/dist", "--promotable"), &out, &errOut); code != 1 {
		t.Fatalf("runOrigin --promotable on a static dist = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "needs an oci:// --mirror-from") {
		t.Errorf("the refusal does not say why: %q", errOut.String())
	}

	f := promoteFactory()
	f.mirror = "https://static.example/dist"
	if _, err := f.promotableOrigin("lz4.org", "1.10.0"); err == nil ||
		!strings.Contains(err.Error(), "needs an oci:// --mirror-from") {
		t.Errorf("promotableOrigin on a static dist: %v", err)
	}
}

// why names a bootstrap value that is neither 0 nor 1.
func TestWhyNamesAnUnreadableBootstrapValue(t *testing.T) {
	got := provOrigin{Bootstrap: "yes"}.why()
	if !strings.Contains(got, "bootstrap=yes") || !strings.Contains(got, "neither 0 nor 1") {
		t.Errorf("why() = %q", got)
	}
}

// The default reader refuses a base that is not an OCI registry instead of
// answering with an empty read.
func TestSourceVerifiedRefusesANonOCIBase(t *testing.T) {
	digest, payloads, refs, err := sourceVerified("https://static.example/dist", "lz4.org", "1.10.0", "linux", "s390x")
	if err == nil {
		t.Fatal("a non-OCI base was read")
	}
	if digest != "" || payloads != nil || refs != nil {
		t.Errorf("a failed read returned data: %q %v %v", digest, payloads, refs)
	}
}

// With a well-formed registry that cannot be reached, the read fails and
// returns nothing: "could not ask" is an error, never an empty answer.
func TestSourceVerifiedFailsOnAnUnreachableRegistry(t *testing.T) {
	digest, payloads, refs, err := sourceVerified("oci://127.0.0.1:1/seed", "lz4.org", "1.10.0", "linux", "s390x")
	if err == nil {
		t.Fatal("an unreachable registry was read")
	}
	if digest != "" || payloads != nil || refs != nil {
		t.Errorf("a failed read returned data: %q %v %v", digest, payloads, refs)
	}
}
