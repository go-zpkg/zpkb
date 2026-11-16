package schema_test

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
)

// ⛔ A SUITE THAT PASSES WITHOUT A CASE FOR THE NEW KEY PROVES NOTHING. The
// schema's propertyNames moved from depKey to depMapKey; these are the cases
// that make the move checkable in both directions.
func TestVersionScopeKeyIsAccepted(t *testing.T) {
	const yaml = `
distributable:
  url: https://example.org/x-{{version}}.tar.gz
versions:
  - 1.0.0
build:
  dependencies:
    python.org: '>=3'
    '<18':
      python.org: '>=3<3.12'
    '>=18':
      python.org: '>=3.12'
  script: make install
`
	if err := pantry.Validate([]byte(yaml)); err != nil {
		t.Fatalf("a version-scoped dependency map was refused: %v", err)
	}
}

// Every spelling the doc comment promises, so the pattern and the prose cannot
// drift apart.
func TestVersionScopeKeySpellings(t *testing.T) {
	for _, key := range []string{"<18", ">=3<3.12", "^2", "~3.5", "=5.40", "*", ">=1.2.3"} {
		yaml := `
distributable: https://example.org/x.tar.gz
versions:
  - 1.0.0
dependencies:
  '` + key + `':
    zlib.net: '^1'
`
		if err := pantry.Validate([]byte(yaml)); err != nil {
			t.Errorf("version scope %q was refused: %v", key, err)
		}
	}
}

// ⭐ AND THE DIRECTION THAT MATTERS MORE: a project name still reads as a
// project, including the 26 pantry projects beginning with `v` that a
// first-character test would have mistaken for version ranges.
func TestProjectNamesStillValidate(t *testing.T) {
	for _, key := range []string{"valgrind.org", "vitejs.dev", "vim.org", "v2raya.org", "5.40", "x86-64", "linux/aarch64"} {
		yaml := `
distributable: https://example.org/x.tar.gz
versions:
  - 1.0.0
dependencies:
  '` + key + `':
    zlib.net: '^1'
`
		if err := pantry.Validate([]byte(yaml)); err != nil {
			t.Errorf("key %q was refused: %v", key, err)
		}
	}
}

// ⛔ THE BREAK CHECK. Widening a key is only safe if something still refuses a
// malformed one — otherwise `propertyNames` has become decoration. A bare `.`
// is not a legal depKey segment and carries no operator, so it is neither kind
// of key.
func TestMalformedDepKeyStillRefused(t *testing.T) {
	for _, key := range []string{".", "..", "a//b"} {
		yaml := `
distributable: https://example.org/x.tar.gz
versions:
  - 1.0.0
dependencies:
  '` + key + `': '^1'
`
		if err := pantry.Validate([]byte(yaml)); err == nil {
			t.Errorf("malformed dependency key %q was accepted", key)
		}
	}
}
