package schema_test

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
)

// `platforms` on a `sources` entry uses the recipe-level key's spelling and
// refuses what names no machine.
func TestSourcePlatformsAreAcceptedAndRefused(t *testing.T) {
	const entry = `
sources:
  - url: https://example.org/go.tar.gz
    sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
`
	for _, c := range []struct {
		what, platforms string
		ok              bool
	}{
		{"an os/arch list", "    platforms: [linux/x86-64, darwin/aarch64]\n", true},
		{"a bare OS", "    platforms: linux\n", true},
		{"a list of OS names", "    platforms: [linux, darwin]\n", true},
		{"an unknown OS", "    platforms: [plan9/x86-64]\n", false},
		{"an unknown arch", "    platforms: [linux/x86_64]\n", false},
		{"an arch that is not this OS's", "    platforms: [linux/wasm]\n", false},
		{"an empty list", "    platforms: []\n", false},
		{"a number", "    platforms: [1]\n", false},
	} {
		err := pantry.Validate([]byte(sourcesHead + entry + c.platforms))
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.what, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: validated", c.what)
		}
	}
}
