package build

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/fixup"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

func TestRootfsSubdir(t *testing.T) {
	for name, tc := range map[string]struct {
		build   any
		want    string
		wantErr string
	}{
		"script shorthand": {build: "make", want: ""},
		"absent":           {build: map[string]any{"script": "make"}, want: ""},
		"set":              {build: map[string]any{"rootfs": "rootfs"}, want: "rootfs"},
		"wrong type":       {build: map[string]any{"rootfs": []any{"a"}}, wantErr: "must be a string"},
		"absolute":         {build: map[string]any{"rootfs": "/etc"}, wantErr: "relative"},
		"dotdot":           {build: map[string]any{"rootfs": "../x"}, wantErr: "clean relative"},
		"empty":            {build: map[string]any{"rootfs": ""}, wantErr: "empty"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RootfsSubdir(&pantry.Recipe{Build: tc.build})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestBuildHandsTheRootfsAndItsDependenciesToFixUp: the opt-in key and the
// closure's search path reach the fix-up, and a recipe without the key passes
// neither (the dependency list is the closure of the build, and handing it to
// every fix-up would be a search path nobody asked for).
func TestBuildHandsTheRootfsAndItsDependenciesToFixUp(t *testing.T) {
	for _, withKey := range []bool{true, false} {
		tenv(t)
		tgt := target.Target{Platform: "linux", Arch: "x86-64"}
		var got fixup.Options
		r := okRunner("example.com/img", tgt)
		r.FixUp = func(o fixup.Options) error { got = o; return nil }
		r.ResolveDep = func(string, string) (string, error) { return "1.3.1", nil }
		recipe := okRecipe()
		recipe.Dependencies = map[string]any{"zlib.net": "^1"}
		if withKey {
			recipe.Build = map[string]any{"script": []any{"make install"}, "rootfs": "rootfs"}
		}
		if _, err := r.Build(recipe, "example.com/img", "*", tgt, tgt, ""); err != nil {
			t.Fatal(err)
		}
		if withKey {
			if got.Rootfs != "rootfs" || len(got.RootfsDeps) == 0 || !strings.Contains(got.RootfsDeps[0], "zlib.net") {
				t.Errorf("with the key: %+v", got)
			}
		} else if got.Rootfs != "" || got.RootfsDeps != nil {
			t.Errorf("without the key: %+v", got)
		}
	}
}
