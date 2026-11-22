package fixup

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootfsClosureKeepsAnExistingUsrLibRunpathEntry(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.rootfs, "usr/bin/app")
	putFile(t, p, synth{runpath: "/opt/store/x/lib:/usr/lib"}.bytes())
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if got := runpathOf(t, p); got != "/usr/lib" {
		t.Fatalf("RUNPATH = %q, want the store entry dropped and /usr/lib kept once", got)
	}
}

func TestRootfsClosureSkipsProgramHeadersBeforeTheLoader(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test", leadingLoad: true}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/ld.so.test"), synth{}.bytes())
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if !isThere(filepath.Join(f.rootfs, "lib64/ld.so.test")) {
		t.Fatal("the loader behind a PT_LOAD was not found")
	}
}

func TestResolveInChrootReadsAnAbsoluteLinkFromTheRoot(t *testing.T) {
	root := t.TempDir()
	putFile(t, filepath.Join(root, "d/file"), []byte("x"))
	link(t, "/d", filepath.Join(root, "l"))
	p, err := resolveIn(root, "l/file", true, false)
	if err != nil || p != filepath.Join(root, "d/file") {
		t.Fatalf("%q %v", p, err)
	}
}

func TestCloseRootfsRefusesAMissingRootfs(t *testing.T) {
	_, err := CloseRootfs(t.TempDir(), "rootfs", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rootfs:") {
		t.Fatalf("got %v", err)
	}
}

func TestCloseRootfsIgnoresDependencyPrefixesThatAreNotDirectories(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
	notDir := filepath.Join(filepath.Dir(f.dep), "afile")
	putFile(t, notDir, []byte("x"))
	deps := []string{filepath.Join(filepath.Dir(f.dep), "missing"), notDir, f.dep, f.dep}
	if _, err := CloseRootfs(f.prefix, "rootfs", deps, nil); err != nil {
		t.Fatal(err)
	}
	if !isThere(filepath.Join(f.rootfs, "usr/lib/libA.so.1")) {
		t.Fatal("the real prefix was not searched")
	}
}

func TestRootfsClosureQuotesAtMostMaxReportedFailures(t *testing.T) {
	f := newFixture(t)
	var needed []string
	for i := 0; i < maxReportedFails+5; i++ {
		needed = append(needed, fmt.Sprintf("libgone%02d.so.1", i))
	}
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: needed}.bytes())
	_, err := f.run(t)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "... and 5 more") || strings.Contains(err.Error(), "libgone24") {
		t.Fatalf("got %v", err)
	}
}
