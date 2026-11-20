package main

import (
	"reflect"
	"testing"

	"github.com/go-attest/sbom/provenance"
	"github.com/go-zpkg/zpkb/build"
)

// Every entry of the recipe's `sources:` is a material of the build, after the
// main one and in order — they are bytes the artifact was built from.
func TestMaterialsOfRecordsEverySource(t *testing.T) {
	const a = "aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333"
	const b = "bbbb3333bbbb3333bbbb3333bbbb3333bbbb3333bbbb3333bbbb3333bbbb3333"
	const c = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"
	got := materialsOf(build.SourceRef{
		URI: "https://x/main.tar.gz", SHA256: a,
		Extra: []build.SourceRef{
			{URI: "https://x/tk.tar.gz", SHA256: b},
			{URI: "https://x/undigested", SHA256: ""}, // says nothing checkable: no material
			{URI: "https://x/fix.patch", SHA256: c},
		},
	})
	want := []provenance.Material{
		{URI: "https://x/main.tar.gz", SHA256: a},
		{URI: "https://x/tk.tar.gz", SHA256: b},
		{URI: "https://x/fix.patch", SHA256: c},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("materials = %+v, want %+v", got, want)
	}

	// A recipe with sources and no main source still records them.
	if got := materialsOf(build.SourceRef{Extra: []build.SourceRef{{URI: "https://x/a", SHA256: a}}}); len(got) != 1 {
		t.Errorf("materials = %+v", got)
	}
}
