package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/moustache"
)

// A prefix the installer marked as seed-installed must not feed a build that
// stages itself as unseeded: the marker is written by the installer, where a
// build that never saw the seed flag cannot have left it out.
func TestAnUnseededPlanRefusesAPrefixTheInstallerMarkedAsSeeded(t *testing.T) {
	root := t.TempDir()
	marked := filepath.Join(root, "marked")
	plain := filepath.Join(root, "plain")
	for _, d := range []string{marked, plain} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(marked, artifact.SeedMarkerName), []byte("sha256:x\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	env := []moustache.Dep{
		{Project: "gnu.org/make", Version: "4.4.1", Path: plain},
		{Project: "llvm.org", Version: "23.1.2", Path: marked},
	}
	err := refuseSeededPrefixes(env, false)
	if err == nil || !strings.Contains(err.Error(), "llvm.org") || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("an unseeded plan accepted a seed-marked prefix: %v", err)
	}
	if strings.Contains(err.Error(), "gnu.org/make") {
		t.Errorf("the unmarked dependency was named: %v", err)
	}
	// Under a seed the marker is expected, and an unmarked prefix is one this
	// pass built itself.
	if err := refuseSeededPrefixes(env, true); err != nil {
		t.Errorf("a seeded plan was refused: %v", err)
	}
	if err := refuseSeededPrefixes(env[:1], false); err != nil {
		t.Errorf("unmarked prefixes were refused: %v", err)
	}
	// A dependency with no path (resolved nothing on disk) is not a prefix.
	if err := refuseSeededPrefixes([]moustache.Dep{{Project: "x", Version: "1"}}, false); err != nil {
		t.Errorf("a dependency without a path was refused: %v", err)
	}
	// A marker that cannot be read is a refusal, never a pass.
	bad := filepath.Join(root, "file")
	if err := os.WriteFile(bad, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := refuseSeededPrefixes([]moustache.Dep{{Project: "y", Version: "1", Path: bad}}, false); err == nil {
		t.Error("an unreadable marker passed")
	}
}
