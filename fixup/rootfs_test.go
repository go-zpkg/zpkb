package fixup

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// synth describes a synthetic ELF64 little-endian shared object, built in the
// test so that no binary is committed and every field is under the test's eye.
type synth struct {
	needed  []string
	runpath string
	interp  string
	dlopen  string // JSON of one .note.dlopen note; "" for none
}

func dlopenNote(json string) []byte {
	var b bytes.Buffer
	desc := append([]byte(json), 0)
	for _, v := range []uint32{4, uint32(len(desc)), dlopenNoteType} {
		_ = binary.Write(&b, binary.LittleEndian, v)
	}
	b.WriteString("FDO\x00")
	b.Write(desc)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func (s synth) bytes() []byte {
	le := binary.LittleEndian
	dynstr := []byte{0}
	add := func(str string) uint64 {
		off := uint64(len(dynstr))
		dynstr = append(append(dynstr, str...), 0)
		return off
	}
	var dyn bytes.Buffer
	entry := func(tag, val uint64) {
		_ = binary.Write(&dyn, le, tag)
		_ = binary.Write(&dyn, le, val)
	}
	for _, n := range s.needed {
		entry(1, add(n)) // DT_NEEDED
	}
	if s.runpath != "" {
		entry(29, add(s.runpath)) // DT_RUNPATH
	}
	entry(0, 0)

	var note []byte
	if s.dlopen != "" {
		note = dlopenNote(s.dlopen)
	}
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.note.dlopen\x00.shstrtab\x00")
	nameOf := func(n string) uint32 { return uint32(bytes.Index(shstr, []byte(n+"\x00"))) }

	phnum := 0
	var interp []byte
	if s.interp != "" {
		phnum = 1
		interp = append([]byte(s.interp), 0)
	}
	off := uint64(64 + 56*phnum)
	interpOff := off
	off += uint64(len(interp))
	dynstrOff := off
	off += uint64(len(dynstr))
	dynOff := off
	off += uint64(dyn.Len())
	noteOff := off
	off += uint64(len(note))
	shstrOff := off
	off += uint64(len(shstr))
	shoff := (off + 7) &^ 7

	type sh struct {
		name, typ      uint32
		flags, addr    uint64
		offset, size   uint64
		link, info     uint32
		align, entsize uint64
	}
	shs := []sh{
		{},
		{nameOf(".dynstr"), 3, 0, 0, dynstrOff, uint64(len(dynstr)), 0, 0, 1, 0},
		{nameOf(".dynamic"), 6, 0, 0, dynOff, uint64(dyn.Len()), 1, 0, 8, 16},
	}
	if note != nil {
		shs = append(shs, sh{nameOf(".note.dlopen"), 7, 0, 0, noteOff, uint64(len(note)), 0, 0, 4, 0})
	}
	shs = append(shs, sh{nameOf(".shstrtab"), 3, 0, 0, shstrOff, uint64(len(shstr)), 0, 0, 1, 0})

	var out bytes.Buffer
	out.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	for _, v := range []any{
		uint16(3), uint16(62), uint32(1), uint64(0), uint64(64), shoff, uint32(0),
		uint16(64), uint16(56), uint16(phnum), uint16(64), uint16(len(shs)), uint16(len(shs) - 1),
	} {
		_ = binary.Write(&out, le, v)
	}
	if phnum == 1 {
		for _, v := range []any{uint32(3), uint32(4), interpOff, uint64(0), uint64(0), uint64(len(interp)), uint64(len(interp)), uint64(1)} {
			_ = binary.Write(&out, le, v)
		}
	}
	out.Write(interp)
	out.Write(dynstr)
	out.Write(dyn.Bytes())
	out.Write(note)
	out.Write(shstr)
	for uint64(out.Len()) < shoff {
		out.WriteByte(0)
	}
	for _, h := range shs {
		_ = binary.Write(&out, le, h)
	}
	return out.Bytes()
}

func putFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

type fixture struct {
	prefix, rootfs, dep string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	d := t.TempDir()
	f := fixture{prefix: filepath.Join(d, "pkg"), dep: filepath.Join(d, "dep")}
	f.rootfs = filepath.Join(f.prefix, "rootfs")
	if err := os.MkdirAll(f.rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.dep, 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) run(t *testing.T) (RootfsReport, error) {
	t.Helper()
	return CloseRootfs(f.prefix, "rootfs", []string{f.dep}, nil)
}

func isThere(p string) bool { _, err := os.Stat(p); return err == nil }

func TestRootfsClosureCopiesNeededTransitivelyAndTheLoader(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}, interp: "/lib64/ld.so.test"}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1.2"), synth{needed: []string{"libB.so.2"}}.bytes())
	link(t, "libA.so.1.2", filepath.Join(f.dep, "lib/libA.so.1"))
	putFile(t, filepath.Join(f.dep, "lib/libB.so.2"), synth{}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/ld.so.test"), synth{}.bytes())

	rep, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"libA.so.1", "libA.so.1.2", "libB.so.2", "ld.so.test"} {
		if !isThere(filepath.Join(f.rootfs, "usr/lib", n)) {
			t.Errorf("%s not copied: %v", n, rep.Copied)
		}
	}
	// The loader path the binary names resolves inside the rootfs.
	l := filepath.Join(f.rootfs, "lib64/ld.so.test")
	if tgt, err := os.Readlink(l); err != nil || filepath.IsAbs(tgt) {
		t.Errorf("loader link: %q %v", tgt, err)
	}
	if !isThere(l) {
		t.Error("loader link dangles")
	}
	if rep.ELFs != 4 {
		t.Errorf("ELFs = %d, want 4 (app, libA, libB, loader)", rep.ELFs)
	}
}

func TestRootfsClosureLeavesWhatTheRootfsAlreadyHas(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}}.bytes())
	putFile(t, filepath.Join(f.rootfs, "usr/lib/libA.so.1"), synth{}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{needed: []string{"libNOPE.so"}}.bytes())
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if isThere(filepath.Join(f.rootfs, "usr/lib/libNOPE.so")) {
		t.Error("the dependency's copy replaced the rootfs's own")
	}
}

func TestRootfsClosureRefusesAnUnresolvedNeeded(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libgone.so.9"}}.bytes())
	_, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), "libgone.so.9") || !strings.Contains(err.Error(), "usr/bin/app") {
		t.Fatalf("want an error naming the library and the binary, got %v", err)
	}
}

func TestRootfsClosureRefusesAMissingLoader(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{interp: "/lib64/ld.so.test"}.bytes())
	_, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("got %v", err)
	}
}

func TestRootfsClosureDlopenPriorities(t *testing.T) {
	f := newFixture(t)
	json := `[{"feature":"tpm","description":"tpm2","priority":"recommended","soname":["libtss.so.2"]},` +
		`{"feature":"idn","priority":"suggested","soname":["libidn.so.12","libidn2.so.0"]},` +
		`{"feature":"nopri","soname":["libnopri.so.1"]}]`
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: json}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libidn2.so.0"), synth{}.bytes()) // the second alternative
	rep, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if !isThere(filepath.Join(f.rootfs, "usr/lib/libidn2.so.0")) {
		t.Error("the available alternative was not copied")
	}
	if len(rep.Misses) != 2 {
		t.Fatalf("misses = %+v, want tpm and nopri", rep.Misses)
	}
	for _, m := range rep.Misses {
		if m.Priority != PriorityRecommended { // tpm, and nopri which defaults to it
			t.Errorf("miss %+v: want priority recommended", m)
		}
		if m.Needer != filepath.Join("usr/bin/app") {
			t.Errorf("needer = %q", m.Needer)
		}
	}
}

func TestRootfsClosureRefusesARequiredDlopen(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"),
		synth{dlopen: `[{"feature":"core","priority":"required","soname":["libcore.so.1"]}]`}.bytes())
	_, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), "required") || !strings.Contains(err.Error(), "libcore.so.1") {
		t.Fatalf("got %v", err)
	}
}

func TestRootfsClosureRefusesABadNote(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{dlopen: `[{"soname":[]}]`}.bytes())
	if _, err := f.run(t); err == nil {
		t.Fatal("an entry with no soname was accepted")
	}
}

func TestRootfsClosureNeverFollowsASymlinkOutOfADependency(t *testing.T) {
	for name, target := range map[string]func(outside string) string{
		"relative": func(string) string { return "../../outside/libX.so.1" },
		"absolute": func(outside string) string { return outside },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			outside := filepath.Join(filepath.Dir(f.prefix), "outside", "libX.so.1")
			putFile(t, outside, synth{}.bytes())
			putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libX.so.1"}}.bytes())
			link(t, target(outside), filepath.Join(f.dep, "lib/libX.so.1"))
			_, err := f.run(t)
			if err == nil || !strings.Contains(err.Error(), "refused") {
				t.Fatalf("an escaping symlink was followed or not named: %v", err)
			}
			if isThere(filepath.Join(f.rootfs, "usr/lib/libX.so.1")) {
				t.Error("the outside file was copied")
			}
		})
	}
}

func TestRootfsClosureEndsOnASymlinkLoop(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libL.so.1"}}.bytes())
	link(t, "libM.so.1", filepath.Join(f.dep, "lib/libL.so.1"))
	link(t, "libL.so.1", filepath.Join(f.dep, "lib/libM.so.1"))
	_, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), "libL.so.1") {
		t.Fatalf("got %v", err)
	}
}

func TestRootfsClosureReadsTheRootfsAsAChroot(t *testing.T) {
	// /lib -> /usr/lib with an ABSOLUTE target is how a merged-usr rootfs is
	// written; it must resolve inside the rootfs, not on the host.
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}}.bytes())
	putFile(t, filepath.Join(f.rootfs, "usr/lib/libA.so.1"), synth{}.bytes())
	link(t, "/usr/lib", filepath.Join(f.rootfs, "lib"))
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{needed: []string{"libNOPE.so"}}.bytes())
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
}

func TestRootfsClosureRefusesARootfsThatIsASymlink(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.rootfs); err != nil {
		t.Fatal(err)
	}
	link(t, f.dep, f.rootfs)
	if _, err := f.run(t); err == nil {
		t.Fatal("a symlinked rootfs was walked")
	}
}

func TestRootfsClosureIgnoresNonELF(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "etc/os-release"), []byte("NAME=x\n"))
	putFile(t, filepath.Join(f.rootfs, "tiny"), []byte("\x7fE"))
	rep, err := f.run(t)
	if err != nil || rep.ELFs != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRootfsClosureHonoursRunpathOrigin(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/lib/systemd/systemd"), synth{needed: []string{"libshared.so"}, runpath: "$ORIGIN"}.bytes())
	putFile(t, filepath.Join(f.rootfs, "usr/lib/systemd/libshared.so"), synth{}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libshared.so"), synth{needed: []string{"libNOPE.so"}}.bytes())
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
}

func TestValidRootfsSubdir(t *testing.T) {
	for _, ok := range []string{"rootfs", "image/root"} {
		if err := ValidRootfsSubdir(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/", "/etc", ".", "..", "../x", "a/../b", "a//b", "a/", "./a", "a\\b", "a\x00b"} {
		if err := ValidRootfsSubdir(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFixUpRefusesARootfsOnDarwin(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := FixUp(Options{Prefix: d, Platform: "darwin", Rootfs: "rootfs"})
	if err == nil || !strings.Contains(err.Error(), "ELF-only") {
		t.Fatalf("got %v", err)
	}
}

func TestFixUpRunsTheRootfsClosureOnLinux(t *testing.T) {
	f := newFixture(t)
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
	var logs []string
	err := FixUp(Options{Prefix: f.prefix, Platform: "linux", Rootfs: "rootfs", RootfsDeps: []string{f.dep}, Log: func(s string) { logs = append(logs, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if !isThere(filepath.Join(f.rootfs, "usr/lib/libA.so.1")) {
		t.Error("closure did not run")
	}
	if !strings.Contains(strings.Join(logs, "\n"), "rootfs closure:") {
		t.Errorf("no summary line: %v", logs)
	}
}

func runpathOf(t *testing.T, p string) string {
	t.Helper()
	f, err := elf.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v, _ := f.DynString(elf.DT_RUNPATH)
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func TestRootfsClosureRewritesStoreRunpaths(t *testing.T) {
	f := newFixture(t)
	store := "/opt/store/zlib.net/v1.3/lib"
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"),
		synth{needed: []string{"libA.so.1"}, runpath: store + ":$ORIGIN/../lib:$ORIGIN/../../../elsewhere"}.bytes())
	// Already clean: its bytes must not be touched.
	putFile(t, filepath.Join(f.rootfs, "usr/lib/systemd/systemd"), synth{runpath: "$ORIGIN"}.bytes())
	// A copied library carries the store's RUNPATH too.
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{runpath: "$ORIGIN/../../libB/v2/lib:" + store}.bytes())
	rep, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := runpathOf(t, filepath.Join(f.rootfs, "usr/bin/app")); got != "$ORIGIN/../lib:/usr/lib" {
		t.Errorf("app RUNPATH = %q", got)
	}
	if got := runpathOf(t, filepath.Join(f.rootfs, "usr/lib/systemd/systemd")); got != "$ORIGIN" {
		t.Errorf("clean RUNPATH rewritten to %q", got)
	}
	if got := runpathOf(t, filepath.Join(f.rootfs, "usr/lib/libA.so.1")); got != "/usr/lib" {
		t.Errorf("copied lib RUNPATH = %q", got)
	}
	if rep.Rewritten != 2 {
		t.Errorf("Rewritten = %d, want 2", rep.Rewritten)
	}
	// The dependency's own file is not the one rewritten.
	if got := runpathOf(t, filepath.Join(f.dep, "lib/libA.so.1")); !strings.Contains(got, store) {
		t.Errorf("the dependency prefix was modified: %q", got)
	}
}

func TestRootfsClosureFollowsUsrMergeAndNeverLeavesTheRootfs(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(filepath.Dir(f.prefix), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	putFile(t, filepath.Join(f.rootfs, "usr/bin/app"), synth{needed: []string{"libA.so.1"}, interp: "/lib64/ld.so.test"}.bytes())
	link(t, "usr/bin", filepath.Join(f.rootfs, "bin"))         // relative usr-merge
	link(t, "/usr/bin", filepath.Join(f.rootfs, "sbin"))       // absolute: a chroot target
	link(t, "usr/lib", filepath.Join(f.rootfs, "lib"))         // loader and libs land through it
	link(t, "../../outside", filepath.Join(f.rootfs, "lib64")) // tries to leave
	putFile(t, filepath.Join(f.dep, "lib/libA.so.1"), synth{}.bytes())
	putFile(t, filepath.Join(f.dep, "lib/ld.so.test"), synth{}.bytes())
	rep, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ELFs != 3 { // app once (not again through bin/ and sbin/), libA, loader
		t.Errorf("ELFs = %d, want 3", rep.ELFs)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("something was written outside the rootfs: %v", ents)
	}
	// ".." is clamped at the rootfs root, so the link landed INSIDE it.
	if _, err := os.Lstat(filepath.Join(f.rootfs, "outside/ld.so.test")); err != nil {
		t.Errorf("clamped loader link missing: %v", err)
	}
}
