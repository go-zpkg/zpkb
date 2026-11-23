package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// fakeSource is a registry whose tags are exactly `tags`; a tag holds `plats`
// platforms. A read of a tag it does not hold answers "not found", as a registry
// does for the bare version of a build published under `<version>-h<hash>`.
type fakeSource struct {
	tags  []string
	noPlt map[string]bool // tags that do NOT carry linux/x86-64
	read  []string        // tags the read asked for
	lerr  error
}

func (f *fakeSource) ListTags(string) ([]string, error) { return f.tags, f.lerr }
func (f *fakeSource) HasPlatform(_, ver, _, _ string) (bool, error) {
	for _, t := range f.tags {
		if t == ver {
			return !f.noPlt[t], nil
		}
	}
	return false, nil
}
func (f *fakeSource) ArtifactDigest(_, ver, _, _ string) (string, error) {
	f.read = append(f.read, ver)
	if ok, _ := f.HasPlatform("", ver, "", ""); !ok {
		return "", errors.New(ver + ": not found")
	}
	return "sha256:abc", nil
}
func (f *fakeSource) VerifiedPayloads(_, _, _, _, _ string) ([][]byte, error) { return nil, nil }
func (f *fakeSource) FetchAttestations(_, _, _, _ string) ([]artifact.Referrer, map[string]string, error) {
	return nil, nil, nil
}

const buildA = "1.11.1-h2v47zu5ezpvvks5v"
const buildB = "1.11.1-hbbbbbbbbbbbbbbbb"

// ⛔ THE FAILURE OF promo-r1 (go-zpkg/packages run 45140545009): the registry
// held `1.11.1-h<hash>` only, and the read asked for `1.11.1`.
func TestAMirrorReadsTheBuildTagNotTheBareVersion(t *testing.T) {
	f := &fakeSource{tags: []string{buildA}}
	if _, _, _, err := readVerifiedVia(f, "lz4.org", "1.11.1", "linux", "x86-64"); err != nil {
		t.Fatalf("a version published only as %s was not found: %v", buildA, err)
	}
	if len(f.read) != 1 || f.read[0] != buildA {
		t.Errorf("read tags = %v, want [%s]", f.read, buildA)
	}
}

func TestResolveBuildTagRule(t *testing.T) {
	for _, c := range []struct {
		name string
		src  *fakeSource
		in   string
		want string
		err  string
	}{
		{"one build", &fakeSource{tags: []string{"1.10.0", buildA, "1.9.0-hcccccccccccccccc"}}, "1.11.1", buildA, ""},
		{"a given build tag is kept", &fakeSource{tags: []string{buildA, buildB}}, buildB, buildB, ""},
		{"bare tag of an unhashed publication", &fakeSource{tags: []string{"1.11.1"}}, "1.11.1", "1.11.1", ""},
		{"absent: the bare tag, whose read says not found", &fakeSource{tags: []string{"1.10.0"}}, "1.11.1", "1.11.1", ""},
		{"two builds are refused", &fakeSource{tags: []string{buildB, buildA}}, "1.11.1", "", buildA + ", " + buildB},
		{"a build without this platform does not count", &fakeSource{tags: []string{buildA, buildB}, noPlt: map[string]bool{buildB: true}}, "1.11.1", buildA, ""},
		{"1.11.10 is not 1.11.1", &fakeSource{tags: []string{"1.11.10-hbbbbbbbbbbbbbbbb"}}, "1.11.1", "1.11.1", ""},
		{"listing failure is an error", &fakeSource{lerr: errors.New("boom")}, "1.11.1", "", "boom"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveBuildTag(c.src, "lz4.org", c.in, "linux", "x86-64")
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want it to contain %q", err, c.err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Errorf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
