package hcl

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
)

const curlHCL = `
distributable {
  url              = "https://curl.se/download/curl-{{version}}.tar.bz2"
  strip-components = 1
}
display-name = "cURL"
versions {
  github = "curl/curl/releases"
  strip  = "/^curl /"
}
dependencies = { "openssl.org" = "^1.1", "zlib.net" = "^1.2.11" }
build {
  script = ["./configure $ARGS", "make --jobs {{ hw.concurrency }} install"]
  env    = { ARGS = ["--prefix={{prefix}}", "--with-openssl"] }
}
test     = ["curl -i pkgx.sh"]
provides = ["bin/curl", "bin/curl-config"]
`

const curlYAML = `
distributable:
  url: https://curl.se/download/curl-{{version}}.tar.bz2
  strip-components: 1
display-name: cURL
versions:
  github: curl/curl/releases
  strip: /^curl /
dependencies:
  openssl.org: ^1.1
  zlib.net: ^1.2.11
build:
  script:
    - ./configure $ARGS
    - make --jobs {{ hw.concurrency }} install
  env:
    ARGS:
      - --prefix={{prefix}}
      - --with-openssl
test:
  - curl -i pkgx.sh
provides:
  - bin/curl
  - bin/curl-config
`

func TestHCLEquivalentToYAML(t *testing.T) {
	fromHCL, err := Parse([]byte(curlHCL), "package.hcl")
	if err != nil {
		t.Fatalf("HCL parse: %v", err)
	}
	fromYAML, err := pantry.Parse([]byte(curlYAML))
	if err != nil {
		t.Fatalf("YAML parse: %v", err)
	}
	if !reflect.DeepEqual(fromHCL, fromYAML) {
		t.Errorf("HCL and YAML recipes differ:\n hcl=%#v\nyaml=%#v", fromHCL, fromYAML)
	}
	if fromHCL.DisplayName != "cURL" {
		t.Errorf("DisplayName=%q", fromHCL.DisplayName)
	}
}

// `sources` written as an HCL list of objects decodes to the same Recipe as the
// YAML list, so the example in the docs is the one the builder reads.
func TestHCLSourcesEquivalentToYAML(t *testing.T) {
	const digest = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
	fromHCL, err := Parse([]byte(`
distributable {
  url = "https://example.org/x-{{version}}.tar.gz"
}
sources = [
  { url = "https://example.org/tk.tar.gz", sha256 = "`+digest+`", dest = "tk", "strip-components" = 1 },
  { url = "https://example.org/fix.patch", sha256 = "`+digest+`", extract = false },
]
`), "package.hcl")
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := pantry.Parse([]byte(`
distributable:
  url: https://example.org/x-{{version}}.tar.gz
sources:
  - url: https://example.org/tk.tar.gz
    sha256: ` + digest + `
    dest: tk
    strip-components: 1
  - url: https://example.org/fix.patch
    sha256: ` + digest + `
    extract: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromHCL, fromYAML) {
		t.Errorf("differ:\n hcl=%#v\nyaml=%#v", fromHCL, fromYAML)
	}
	if lst, ok := fromHCL.Sources.([]any); !ok || len(lst) != 2 {
		t.Errorf("Sources = %#v", fromHCL.Sources)
	}
}

func TestParseSyntaxError(t *testing.T) {
	if _, err := Parse([]byte("build { script = "), "x.hcl"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestParseEvalError(t *testing.T) {
	// a bare reference has no value in a nil eval context
	if _, err := ToMap([]byte("x = undefined_ref\n"), "x.hcl"); err == nil {
		t.Error("expected eval error on undefined reference")
	}
}

func TestParseDuplicateKey(t *testing.T) {
	src := "build { script = [\"a\"] }\nbuild { script = [\"b\"] }\n"
	if _, err := ToMap([]byte(src), "x.hcl"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate-key error, got %v", err)
	}
}

func TestParseSchemaInvalid(t *testing.T) {
	// decodes fine but violates the schema (provides must not be a number)
	if _, err := Parse([]byte("provides = 123\n"), "x.hcl"); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("expected schema error, got %v", err)
	}
}

func TestBlockRecursionError(t *testing.T) {
	// an eval error inside a nested block propagates out of bodyToMap
	if _, err := ToMap([]byte("build {\n  x = undef_ref\n}\n"), "x.hcl"); err == nil {
		t.Error("expected error from block body")
	}
}

func TestParseNestedBlock(t *testing.T) {
	// a block nested in a block round-trips as a nested map
	m, err := ToMap([]byte("build {\n  env { A = \"1\" }\n}\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	build := m["build"].(map[string]any)
	if env, ok := build["env"].(map[string]any); !ok || env["A"] != "1" {
		t.Errorf("nested block = %#v", build)
	}
}
