package fixup

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The guards of the rootfs closure, one test per refusal. Several need a path
// the process may not read or write, which root and Windows cannot be denied.

func needPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a user that file modes bind")
	}
}

// chmod sets a mode for the test and puts 0755 back so TempDir can be removed.
func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
}

func mustFail(t *testing.T, f fixture, want string) {
	t.Helper()
	_, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error containing %q, got %v", want, err)
	}
}

func TestResolveInGuards(t *testing.T) {
	newRoot := func(t *testing.T) string {
		t.Helper()
		return t.TempDir()
	}
	t.Run("missing intermediate without create", func(t *testing.T) {
		if _, err := resolveIn(newRoot(t), "a/b", true, false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing leaf is returned, not created", func(t *testing.T) {
		root := newRoot(t)
		for _, create := range []bool{false, true} {
			p, err := resolveIn(root, "nope", true, create)
			if err != nil || p != filepath.Join(root, "nope") {
				t.Fatalf("create=%v: %q %v", create, p, err)
			}
			if isThere(p) {
				t.Fatalf("create=%v: the leaf was created", create)
			}
		}
	})
	t.Run("intermediates are created", func(t *testing.T) {
		root := newRoot(t)
		p, err := resolveIn(root, "a/b/c", true, true)
		if err != nil || p != filepath.Join(root, "a/b/c") || !isThere(filepath.Join(root, "a/b")) || isThere(p) {
			t.Fatalf("%q %v", p, err)
		}
	})
	t.Run("a file in the middle of the path", func(t *testing.T) {
		root := newRoot(t)
		putFile(t, filepath.Join(root, "f"), []byte("x"))
		if p, err := resolveIn(root, "f/x", true, false); err == nil {
			t.Fatalf("resolved through a file to %q", p)
		}
	})
	t.Run("too many components", func(t *testing.T) {
		// ".." at the root is clamped, so a path of them costs nothing to resolve.
		root := newRoot(t)
		if p, err := resolveIn(root, strings.Repeat("../", maxResolveComps), true, false); err != nil || p != root {
			t.Fatalf("exactly the bound: %q %v", p, err)
		}
		_, err := resolveIn(root, strings.Repeat("../", maxResolveComps+1), true, false)
		if err == nil || !strings.Contains(err.Error(), "too long") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a symlink loop ends in an error", func(t *testing.T) {
		root := newRoot(t)
		link(t, "b", filepath.Join(root, "a"))
		link(t, "a", filepath.Join(root, "b"))
		_, err := resolveIn(root, "a/x", true, false)
		if err == nil || !strings.Contains(err.Error(), "symlinks") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a chain of exactly the bound resolves", func(t *testing.T) {
		root := newRoot(t)
		putFile(t, filepath.Join(root, "end"), []byte("x"))
		prev := "end"
		for i := 0; i < maxResolveLinks; i++ {
			name := "l" + string(rune('A'+i%26)) + string(rune('a'+i/26))
			link(t, prev, filepath.Join(root, name))
			prev = name
		}
		if p, err := resolveIn(root, prev, true, false); err != nil || p != filepath.Join(root, "end") {
			t.Fatalf("%q %v", p, err)
		}
	})
	t.Run("dot-dot above a dependency is refused, not clamped", func(t *testing.T) {
		if _, err := resolveIn(newRoot(t), "../x", false, false); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("readlink failure", func(t *testing.T) {
		root := newRoot(t)
		link(t, "x", filepath.Join(root, "l"))
		old := readlink
		readlink = func(string) (string, error) { return "", errors.New("boom") }
		defer func() { readlink = old }()
		if _, err := resolveIn(root, "l", true, false); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("mkdir refused", func(t *testing.T) {
		needPerms(t)
		root := newRoot(t)
		ro := filepath.Join(root, "ro")
		if err := os.Mkdir(ro, 0o755); err != nil {
			t.Fatal(err)
		}
		chmod(t, ro, 0o555)
		if _, err := resolveIn(root, "ro/a/b", true, true); err == nil {
			t.Fatal("created a directory in a read-only one")
		}
	})
}

func TestValidSoname(t *testing.T) {
	for _, ok := range []string{"libx.so.1", strings.Repeat("a", 255), "a b"} {
		if !validSoname(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 256), ".", "..", "a/b", "../x", "a\x01b", "a\x00b", "a\x7fb"} {
		if validSoname(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidRootfsSubdirNamesAnEmptyKey(t *testing.T) {
	if err := ValidRootfsSubdir(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v", err)
	}
}

func TestCloseRootfsRefusesABadSubdir(t *testing.T) {
	if _, err := CloseRootfs(t.TempDir(), "../x", nil, nil); err == nil || !strings.Contains(err.Error(), "build.rootfs") {
		t.Fatalf("got %v", err)
	}
}

func TestRootfsClosureRefusesATraversingSoname(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"../escape"}}.bytes())
	putFile(t, filepath.Join(f.dep, "escape"), synth{}.bytes())
	mustFail(t, f, "../escape")
	if isThere(filepath.Join(f.rootfs, "usr/lib/escape")) || isThere(filepath.Join(f.rootfs, "usr/escape")) {
		t.Error("a name with a slash in it was installed")
	}
}

func TestRootfsClosureSaysNothingOfRefusalsWhenThereWereNone(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libgone.so.9"}}.bytes())
	_, err := f.run(t)
	if err == nil || strings.Contains(err.Error(), "refused") {
		t.Fatalf("got %v", err)
	}
}

func TestRootfsClosureLoaderGuards(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "ld.so"}.bytes())
		mustFail(t, f, "not an absolute path")
	})
	t.Run("interior NUL", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib/a\x00b"}.bytes())
		mustFail(t, f, "not an absolute path")
	})
	t.Run("no usable name", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/.."}.bytes())
		mustFail(t, f, "no usable name")
	})
	t.Run("already in the rootfs", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test"}.bytes())
		putFile(t, filepath.Join(f.rootfs, "lib64/ld.so.test"), synth{}.bytes())
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("string over the bound", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/x", interpFilesz: maxInterpBytes + 1}.bytes())
		mustFail(t, f, "PT_INTERP of")
	})
	t.Run("string cut short by the file", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/x", interpFilesz: maxInterpBytes}.bytes())
		mustFail(t, f, "PT_INTERP unreadable")
	})
	t.Run("link parent is a file", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test"}.bytes())
		putFile(t, filepath.Join(f.rootfs, "lib64"), []byte("not a directory"))
		putFile(t, filepath.Join(f.dep, "lib/ld.so.test"), synth{}.bytes())
		mustFail(t, f, "lib64")
	})
	t.Run("link refused", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test"}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/ld.so.test"), synth{}.bytes())
		if err := os.Mkdir(filepath.Join(f.rootfs, "lib64"), 0o755); err != nil {
			t.Fatal(err)
		}
		chmod(t, filepath.Join(f.rootfs, "lib64"), 0o555)
		mustFail(t, f, "permission")
	})
	t.Run("loader unreadable", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test"}.bytes())
		src := filepath.Join(f.dep, "lib/ld.so.test")
		putFile(t, src, synth{}.bytes())
		chmod(t, src, 0)
		mustFail(t, f, "permission")
	})
}

func TestRootfsClosureRefusesAnELFItCannotParse(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), []byte("\x7fELF garbage that is no header"))
	mustFail(t, f, "not a readable ELF")
}

func TestRootfsClosureDlopenSectionGuards(t *testing.T) {
	required := `[{"feature":"core","priority":"required","soname":["libcore.so.1"]}]`
	t.Run("a section that is not a note is ignored", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: required, noteType: 1}.bytes())
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("over the bound", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: required, noteSize: maxDlopenBytes + 1}.bytes())
		mustFail(t, f, "limit")
	})
	t.Run("cut short by the file", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: required, noteSize: 1 << 16}.bytes())
		mustFail(t, f, "unreadable")
	})
	t.Run("an alternative that cannot be copied", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: required}.bytes())
		src := filepath.Join(f.dep, "lib/libcore.so.1")
		putFile(t, src, synth{}.bytes())
		chmod(t, src, 0)
		mustFail(t, f, "permission")
	})
}

func TestRootfsClosureWalkGuards(t *testing.T) {
	t.Run("unreadable directory", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		d := filepath.Join(f.rootfs, "secret")
		putFile(t, filepath.Join(d, "x"), []byte("x"))
		chmod(t, d, 0)
		mustFail(t, f, "permission")
	})
	t.Run("unreadable file", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		p := filepath.Join(f.rootfs, "etc/secret")
		putFile(t, p, []byte("x"))
		chmod(t, p, 0)
		mustFail(t, f, "permission")
	})
	t.Run("too many entries", func(t *testing.T) {
		f := newFixture(t)
		for _, n := range []string{"a", "b", "c"} {
			putFile(t, filepath.Join(f.rootfs, n), []byte("x"))
		}
		old := maxRootfsEntries
		maxRootfsEntries = 2
		defer func() { maxRootfsEntries = old }()
		mustFail(t, f, "more than 2 entries")
	})
	t.Run("exactly the bound passes", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "a"), []byte("x")) // root + a = 2 entries
		old := maxRootfsEntries
		maxRootfsEntries = 2
		defer func() { maxRootfsEntries = old }()
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("too many ELF files", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "a"), synth{}.bytes())
		putFile(t, filepath.Join(f.rootfs, "b"), synth{}.bytes())
		old := maxRootfsELFs
		maxRootfsELFs = 1
		defer func() { maxRootfsELFs = old }()
		mustFail(t, f, "more than 1 ELF")
	})
	t.Run("dependency chain too deep", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so"}}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/libA.so"), synth{needed: []string{"libB.so"}}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/libB.so"), synth{}.bytes())
		old := maxRootfsDepth
		maxRootfsDepth = 1
		defer func() { maxRootfsDepth = old }()
		mustFail(t, f, "deeper than 1")
		maxRootfsDepth = 2
		if _, err := newFixtureLike(t).run(t); err != nil {
			t.Fatalf("a chain of exactly the bound was refused: %v", err)
		}
	})
	t.Run("an ELF queued twice is examined once", func(t *testing.T) {
		c := &rootfsCloser{root: "/r", seen: map[string]bool{}}
		for i := 0; i < 2; i++ {
			if err := c.enqueue("/r/x", 0); err != nil {
				t.Fatal(err)
			}
		}
		if len(c.queue) != 1 {
			t.Fatalf("queue = %v", c.queue)
		}
	})
}

// newFixtureLike is a fresh fixture holding the same tree as the chain test's
// first one, so that a second run starts from what the first left untouched.
func newFixtureLike(t *testing.T) fixture {
	t.Helper()
	g := newFixture(t)
	putFile(t, filepath.Join(g.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so"}}.bytes())
	putFile(t, filepath.Join(g.dep, "lib/libA.so"), synth{needed: []string{"libB.so"}}.bytes())
	putFile(t, filepath.Join(g.dep, "lib/libB.so"), synth{}.bytes())
	return g
}

func TestRootfsClosureInstallGuards(t *testing.T) {
	app := synth{needed: []string{"libA.so.1"}}.bytes()
	t.Run("too many libraries", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so", "libB.so"}}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/libA.so"), synth{}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/libB.so"), synth{}.bytes())
		old := maxRootfsLibs
		maxRootfsLibs = 1
		defer func() { maxRootfsLibs = old }()
		mustFail(t, f, "more than 1 libraries")
	})
	t.Run("library over the size bound", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		old := maxLibBytes
		maxLibBytes = 10
		defer func() { maxLibBytes = old }()
		mustFail(t, f, "at most 10 bytes")
	})
	t.Run("library of exactly the size bound", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		b := synth{}.bytes()
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), b)
		old := maxLibBytes
		maxLibBytes = int64(len(b))
		defer func() { maxLibBytes = old }()
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("copy fails midway", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		old := ioCopy
		ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("boom") }
		defer func() { ioCopy = old }()
		mustFail(t, f, "boom")
	})
	t.Run("source vanished", func(t *testing.T) {
		if err := copyBounded(filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "x")); err == nil {
			t.Fatal("copied a file that is not there")
		}
	})
	t.Run("source unreadable", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		src := filepath.Join(f.dep, "lib/libA.so.1")
		putFile(t, src, synth{}.bytes())
		chmod(t, src, 0)
		mustFail(t, f, "permission")
	})
	t.Run("lib dir cannot be made", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		chmod(t, filepath.Join(f.rootfs, "usr"), 0o555)
		mustFail(t, f, "rootfs: usr/lib: ")
	})
	t.Run("lib dir path cannot be resolved", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		link(t, "usr", filepath.Join(f.rootfs, "usr")) // a loop where usr/lib should be
		mustFail(t, f, "usr/lib: usr/lib: more than")
	})
	t.Run("lib dir read-only", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		if err := os.MkdirAll(filepath.Join(f.rootfs, "usr/lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		chmod(t, filepath.Join(f.rootfs, "usr/lib"), 0o555)
		mustFail(t, f, "permission")
	})
	t.Run("lib dir cannot be searched", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
		if err := os.MkdirAll(filepath.Join(f.rootfs, "usr/lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		chmod(t, filepath.Join(f.rootfs, "usr/lib"), 0o644)
		mustFail(t, f, "permission")
	})
	t.Run("soname link refused", func(t *testing.T) {
		needPerms(t)
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), app)
		putFile(t, filepath.Join(f.rootfs, "usr/lib/libA.so.1.2"), synth{}.bytes())
		putFile(t, filepath.Join(f.dep, "lib/libA.so.1.2"), synth{}.bytes())
		link(t, "libA.so.1.2", filepath.Join(f.dep, "lib/libA.so.1"))
		chmod(t, filepath.Join(f.rootfs, "usr/lib"), 0o555)
		mustFail(t, f, "permission")
	})
}

func TestRootfsClosureRunpathGuards(t *testing.T) {
	t.Run("an $ORIGIN above the rootfs is dropped even where clamping would find a directory", func(t *testing.T) {
		f := newFixture(t)
		if err := os.MkdirAll(filepath.Join(f.rootfs, "usr/lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(f.rootfs, "usr/bin/app")
		putFile(t, p, synth{runpath: "$ORIGIN/../../../usr/lib:/opt/store/lib"}.bytes())
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if got := runpathOf(t, p); got != "/usr/lib" {
			t.Errorf("RUNPATH = %q", got)
		}
	})
	t.Run("an $ORIGIN to a file is dropped", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.rootfs, "usr/bin/app")
		putFile(t, p, synth{runpath: "$ORIGIN/../lib/afile:/opt/store/lib"}.bytes())
		putFile(t, filepath.Join(f.rootfs, "usr/lib/afile"), []byte("x"))
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if got := runpathOf(t, p); got != "/usr/lib" {
			t.Errorf("RUNPATH = %q", got)
		}
	})
	t.Run("an $ORIGIN that loops is dropped", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.rootfs, "usr/bin/app")
		putFile(t, p, synth{runpath: "$ORIGIN/loop:/opt/store/lib"}.bytes())
		link(t, "loop", filepath.Join(f.rootfs, "usr/bin/loop"))
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if got := runpathOf(t, p); got != "/usr/lib" {
			t.Errorf("RUNPATH = %q", got)
		}
	})
	t.Run("an entry that is only FHS is left alone", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.rootfs, "usr/bin/app")
		putFile(t, p, synth{runpath: "/usr/lib64/x:/lib64/y:/opt/store/aaaaaaaaaaaaaaaa"}.bytes())
		q := filepath.Join(f.rootfs, "usr/bin/clean")
		putFile(t, q, synth{runpath: "/lib:/lib64:/usr/lib64/zzzzzzzzzzzzzzzzzz"}.bytes())
		if _, err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if got := runpathOf(t, q); got != "/lib:/lib64:/usr/lib64/zzzzzzzzzzzzzzzzzz" {
			t.Errorf("a clean RUNPATH was rewritten to %q", got)
		}
	})
	t.Run("a binary that cannot be rewritten", func(t *testing.T) {
		f := newFixture(t)
		putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{runpath: "/opt/store/lib"}.bytes())
		old := osOpenFile
		osOpenFile = func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("boom") }
		defer func() { osOpenFile = old }()
		mustFail(t, f, "RUNPATH")
	})
}

func TestFixUpReturnsTheClosureError(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libgone.so"}}.bytes())
	err := FixUp(Options{Prefix: f.prefix, Platform: "linux", Rootfs: "rootfs", RootfsDeps: []string{f.dep}})
	if err == nil || !strings.Contains(err.Error(), "libgone.so") {
		t.Fatalf("got %v", err)
	}
}

func TestParseDlopenNotesBound(t *testing.T) {
	if _, err := ParseDlopenNotes(make([]byte, maxDlopenBytes+1), binary.LittleEndian); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
}
