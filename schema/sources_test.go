package schema_test

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
)

const sourcesHead = `
distributable:
  url: https://example.org/x-{{version.raw}}.tar.gz
`

// `sources` is a list in which EVERY entry is fetched, and each is pinned.
func TestSourcesAreAcceptedAndRefused(t *testing.T) {
	const digest = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
	for _, c := range []struct {
		what string
		yaml string
		ok   bool
	}{
		{"an archive with every key", sourcesHead + `
sources:
  - url: https://example.org/tk.tar.gz
    sha256: ` + digest + `
    strip-components: 1
    dest: tk
    extract: true
`, true},
		{"a plain file, sha256 keyed by version", sourcesHead + `
sources:
  - url: https://example.org/fix.patch
    extract: false
    sha256:
      "1.0": ` + digest + `
`, true},
		{"null", sourcesHead + "sources: null\n", true},
		{"a distributable that is one plain file", `
distributable:
  url: https://curl.se/ca/cacert.pem
  extract: false
  sha256: ` + digest + `
`, true},
		{"no sha256", sourcesHead + `
sources:
  - url: https://example.org/tk.tar.gz
`, false},
		{"no url", sourcesHead + `
sources:
  - sha256: ` + digest + `
`, false},
		{"a bare URL string, which has nowhere to put a digest", sourcesHead + `
sources:
  - https://example.org/tk.tar.gz
`, false},
		{"a map instead of a list", sourcesHead + `
sources:
  url: https://example.org/tk.tar.gz
  sha256: ` + digest + `
`, false},
		{"an empty list", sourcesHead + "sources: []\n", false},
		{"an unknown key in an entry", sourcesHead + `
sources:
  - url: https://example.org/tk.tar.gz
    sha256: ` + digest + `
    mirror: https://elsewhere
`, false},
		{"a git ref, which a digest cannot pin", sourcesHead + `
sources:
  - url: https://example.org/tk.git
    ref: v1
    sha256: ` + digest + `
`, false},
		{"a malformed digest", sourcesHead + `
sources:
  - url: https://example.org/tk.tar.gz
    sha256: abc
`, false},
		{"extract that is not a boolean", sourcesHead + `
sources:
  - url: https://example.org/tk.tar.gz
    sha256: ` + digest + `
    extract: "no"
`, false},
	} {
		err := pantry.Validate([]byte(c.yaml))
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.what, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: validated", c.what)
		}
	}
}
