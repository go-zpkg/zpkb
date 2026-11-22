package fixup

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The rootfs closure: a package that installs a root filesystem (for a
// container or a microVM) ships it SELF-CONTAINED, because nothing outside the
// rootfs exists at run time. The recipe opts in with `build.rootfs: <subdir>`
// (a path under the install prefix); every ELF under it is walked, each
// DT_NEEDED and each .note.dlopen soname is searched in the build's dependency
// prefixes, and what is found is copied, transitively, into <subdir>/usr/lib,
// together with the dynamic loader named by PT_INTERP.
//
// What is refused rather than reported:
//
//   - a DT_NEEDED that resolves nowhere (the rootfs would not start);
//   - a dlopen entry of priority "required" with no available soname;
//   - the dynamic loader when it is neither in the rootfs nor in a dependency;
//   - a symlink that leaves the dependency prefix it is read from, or loops.
//
// A "recommended" or "suggested" dlopen entry with no available soname is a
// MISS: reported, not fatal. It is the point of reading the notes at all: a
// rootfs that boots without an optional feature does so silently.
const (
	maxResolveLinks  = 40        // symlinks followed in one resolution, as the kernel's
	maxResolveComps  = 4096      // components pending in one resolution
	maxInterpBytes   = 4096      // a PT_INTERP string
	maxReportedFails = 20        // failures quoted in the error
	rootfsLibDir     = "usr/lib" // where closure libraries land
	maxELFHeaderRead = 4         // bytes read to tell an ELF from anything else
)

// The bounds a test lowers to reach them (a million entries is not a fixture).
var (
	maxRootfsEntries       = 1_000_000 // directory entries walked
	maxRootfsELFs          = 100_000   // ELF files examined
	maxRootfsLibs          = 4096      // libraries copied in
	maxRootfsDepth         = 32        // transitive depth below a rootfs ELF
	maxLibBytes      int64 = 1 << 30   // one copied library
)

// Seams for the two calls whose failure no fixture can provoke: a symlink that
// stops being one between Lstat and Readlink, a read error in the middle of a
// copy.
var (
	readlink = os.Readlink
	ioCopy   = io.Copy
)

// libSearchDirs are searched, in order, inside a dependency prefix and inside
// the rootfs itself.
var libSearchDirs = []string{"usr/lib", "lib", "usr/lib64", "lib64"}

// fhsLib reports whether e is one of the absolute RUNPATH entries that mean the same thing inside
// the rootfs as on any FHS system, and so are kept.
func fhsLib(e string) bool {
	e = filepath.Clean(e)
	switch e {
	case "/lib", "/lib64", "/usr/lib", "/usr/lib64":
		return true
	}
	return strings.HasPrefix(e, "/usr/lib/") || strings.HasPrefix(e, "/usr/lib64/")
}

// rootfsRunpath is the RUNPATH a rootfs ELF should carry, given the one it has.
//
// WHY REWRITE, NOT REMOVE. The binaries come out of a build carrying RUNPATHs
// that name the build's store (absolute, or $ORIGIN-relative across store
// prefixes). Inside the rootfs those name nothing, and worse, on a host that
// still has the store they would load the STORE's copy, not the one the rootfs
// shipped, so the rootfs would work on the machine that built it and nowhere
// else. Removal would be the simple answer but loses the one entry that is
// right and not default: $ORIGIN-relative private library directories
// (systemd's usr/lib/systemd/libsystemd-shared-*.so is found that way), and the
// loader's built-in default directories belong to the glibc that was copied
// in, which may have been configured for a different slibdir. So: keep
// $ORIGIN entries that still resolve INSIDE the rootfs, keep FHS absolute
// entries, drop everything else, and make /usr/lib explicit.
//
// It reports whether the value differs. The rewrite is in place (SetRunpath),
// so the new value is never longer than a store path it replaces; one that
// would not fit is an error rather than a silently kept store RUNPATH.
func (c *rootfsCloser) rootfsRunpath(self, old string) string {
	var keep []string
	have := false
	for _, e := range strings.Split(old, ":") {
		switch {
		case strings.HasPrefix(e, "$ORIGIN") || strings.HasPrefix(e, "${ORIGIN}"):
			r := strings.TrimPrefix(strings.TrimPrefix(e, "$ORIGIN"), "${ORIGIN}")
			abs := filepath.Join(filepath.Dir(self), r)
			if c.isRootfsDir(abs) {
				keep = append(keep, e)
			}
		case fhsLib(e):
			keep = append(keep, e)
			if filepath.Clean(e) == "/usr/lib" {
				have = true
			}
		}
	}
	// Nothing dropped leaves nv == old, and appending /usr/lib to it can only
	// lengthen it, so it does not fit: the bytes stay as they were.
	nv := strings.Join(keep, ":")
	if !have {
		if with := strings.Join(append(keep, "/usr/lib"), ":"); len(with) <= len(old) {
			nv = with
		}
		// else it cannot fit in place; the loader's default directories remain.
	}
	return nv
}

// isRootfsDir reports whether abs lies inside the rootfs and is a directory
// there (symlinks read as the rootfs reads them, never outside it).
func (c *rootfsCloser) isRootfsDir(abs string) bool {
	if abs != c.root && !strings.HasPrefix(abs, c.root+string(filepath.Separator)) {
		return false
	}
	rel, _ := filepath.Rel(c.root, abs) // abs is under root, so Rel cannot fail
	if p, err := resolveIn(c.root, rel, true, false); err == nil {
		fi, err := os.Lstat(p)
		return err == nil && fi.IsDir()
	}
	return false
}

func (c *rootfsCloser) rewriteRunpaths() error {
	paths := make([]string, 0, len(c.seen))
	for p := range c.seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		f, err := elf.Open(p)
		if err != nil {
			continue // reported by examine
		}
		var old string
		for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
			if v, _ := f.DynString(tag); len(v) > 0 {
				old = v[0]
				break
			}
		}
		f.Close()
		if old == "" {
			continue
		}
		nv := c.rootfsRunpath(p, old)
		if nv == old {
			continue
		}
		if err := SetRunpath(p, nv); err != nil {
			return fmt.Errorf("rootfs: %s: RUNPATH %q -> %q: %w", c.rel(p), old, nv, err)
		}
		c.report.Rewritten++
		c.logf("rootfs: RUNPATH of %s: %q -> %q", c.rel(p), old, nv)
	}
	return nil
}

// RootfsMiss is a dlopen entry no soname of which could be found.
type RootfsMiss struct {
	Priority string
	Feature  string
	Sonames  []string
	Needer   string // path of the ELF, relative to the rootfs
}

// RootfsReport says what the closure did.
type RootfsReport struct {
	ELFs   int          // ELF files examined, copied libraries included
	Copied []string     // library names copied into the rootfs lib dir
	Misses []RootfsMiss // recommended/suggested entries not found
	// Rewritten counts ELFs whose RUNPATH was rewritten to resolve inside the rootfs.
	Rewritten int
}

// ValidRootfsSubdir refuses a `build.rootfs` value that is not a plain relative
// path under the prefix.
func ValidRootfsSubdir(sub string) error {
	if sub == "" {
		return errors.New("build.rootfs is empty")
	}
	if strings.ContainsAny(sub, "\x00\\") || filepath.IsAbs(sub) {
		return fmt.Errorf("build.rootfs %q must be a relative path under the prefix", sub)
	}
	if c := filepath.Clean(sub); c != sub || c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return fmt.Errorf("build.rootfs %q must be a clean relative path with no . or .. element", sub)
	}
	return nil
}

func validSoname(s string) bool {
	if s == "" || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if r == '/' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func splitComps(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// resolveIn resolves rel inside root, one component at a time, following every
// symlink itself so that none is followed by the kernel outside the tree.
//
// chroot=true reads an absolute target and a leading .. as relative to root
// (the semantics of a rootfs, whose /usr/lib is root/usr/lib); chroot=false
// REFUSES both, which is how a dependency prefix is read: nothing in it may
// name a path outside itself. Symlinks followed are bounded, so a loop ends.
// create makes missing intermediate directories (the leaf is never created).
// A missing leaf returns its path and a nil error; a missing intermediate is
// fs.ErrNotExist.
func resolveIn(root, rel string, chroot, create bool) (string, error) {
	comps := splitComps(rel)
	cur := root
	links := 0
	// The bound is in the loop header, not in a guard inside it: a guard whose
	// removal leaves a symlink loop spinning forever can only be told apart by a
	// timeout, and a timeout is not an assertion.
	for len(comps) > 0 && links <= maxResolveLinks {
		if len(comps) > maxResolveComps {
			return "", fmt.Errorf("%s: path too long to resolve", rel)
		}
		c := comps[0]
		comps = comps[1:]
		if c == ".." {
			if cur == root {
				if chroot {
					continue
				}
				return "", fmt.Errorf("%s: escapes %s", rel, root)
			}
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			if len(comps) == 0 {
				return next, nil
			}
			if !create {
				return "", err
			}
			if err := os.Mkdir(next, 0o755); err != nil {
				return "", err
			}
			cur = next
			continue
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			links++
			t, err := readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(t) {
				if !chroot {
					return "", fmt.Errorf("%s: absolute symlink %s -> %s leaves %s", rel, next, t, root)
				}
				cur = root
			}
			comps = append(splitComps(t), comps...)
			continue
		}
		cur = next
	}
	if len(comps) > 0 {
		return "", fmt.Errorf("%s: more than %d symlinks (a loop?)", rel, maxResolveLinks)
	}
	return cur, nil
}

type rootfsCloser struct {
	root    string   // the rootfs, real path
	deps    []string // dependency prefixes, real paths
	log     func(string)
	report  RootfsReport
	fails   []string
	queue   []queued
	seen    map[string]bool // real paths already queued
	copied  map[string]bool // names copied
	refused []string        // dependency candidates refused for escaping
}

type queued struct {
	path  string
	depth int
}

func (c *rootfsCloser) logf(f string, a ...any) {
	if c.log != nil {
		c.log(fmt.Sprintf(f, a...))
	}
}

func (c *rootfsCloser) fail(f string, a ...any) { c.fails = append(c.fails, fmt.Sprintf(f, a...)) }

func (c *rootfsCloser) rel(p string) string {
	if r, err := filepath.Rel(c.root, p); err == nil {
		return r
	}
	return p
}

// CloseRootfs runs the closure over <prefix>/<sub>, searching depPaths.
func CloseRootfs(prefix, sub string, depPaths []string, log func(string)) (RootfsReport, error) {
	if err := ValidRootfsSubdir(sub); err != nil {
		return RootfsReport{}, err
	}
	root := filepath.Join(prefix, sub)
	if fi, err := os.Lstat(root); err != nil {
		return RootfsReport{}, fmt.Errorf("rootfs: %w", err)
	} else if !fi.IsDir() {
		return RootfsReport{}, fmt.Errorf("rootfs: %s is not a directory (a symlink there would be followed out of the prefix)", root)
	}
	c := &rootfsCloser{root: root, log: log, seen: map[string]bool{}, copied: map[string]bool{}}
	seenDep := map[string]bool{}
	for _, d := range depPaths {
		// The prefixes are the build's own configuration, so resolving them is
		// trusted; what is INSIDE them is not.
		r, err := filepath.EvalSymlinks(d)
		if err != nil || seenDep[r] {
			continue
		}
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			continue
		}
		seenDep[r] = true
		c.deps = append(c.deps, r)
	}
	if err := c.walk(); err != nil {
		return c.report, err
	}
	for len(c.queue) > 0 {
		q := c.queue[0]
		c.queue = c.queue[1:]
		if err := c.examine(q); err != nil {
			return c.report, err
		}
	}
	if len(c.fails) == 0 {
		if err := c.rewriteRunpaths(); err != nil {
			return c.report, err
		}
	}
	sort.Strings(c.report.Copied)
	if len(c.fails) > 0 {
		sort.Strings(c.fails)
		shown := c.fails
		more := ""
		if len(shown) > maxReportedFails {
			more = fmt.Sprintf("\n  ... and %d more", len(shown)-maxReportedFails)
			shown = shown[:maxReportedFails]
		}
		return c.report, fmt.Errorf("rootfs closure of %s failed (%d):\n  %s%s", root, len(c.fails), strings.Join(shown, "\n  "), more)
	}
	return c.report, nil
}

func (c *rootfsCloser) walk() error {
	n := 0
	return filepath.WalkDir(c.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if n++; n > maxRootfsEntries {
			return fmt.Errorf("rootfs: more than %d entries", maxRootfsEntries)
		}
		if !d.Type().IsRegular() { // WalkDir does not follow symlinks
			return nil
		}
		ok, err := isELFFile(p)
		if err != nil || !ok {
			return err
		}
		return c.enqueue(p, 0)
	})
}

func isELFFile(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var b [maxELFHeaderRead]byte
	n, _ := io.ReadFull(f, b[:])
	return n == len(b) && string(b[:]) == elf.ELFMAG, nil
}

func (c *rootfsCloser) enqueue(p string, depth int) error {
	if c.seen[p] {
		return nil
	}
	if depth > maxRootfsDepth {
		return fmt.Errorf("rootfs: dependency chain deeper than %d at %s", maxRootfsDepth, c.rel(p))
	}
	if len(c.seen) >= maxRootfsELFs {
		return fmt.Errorf("rootfs: more than %d ELF files", maxRootfsELFs)
	}
	c.seen[p] = true
	c.queue = append(c.queue, queued{p, depth})
	return nil
}

// presentInRootfs reports whether the loader would find soname in the rootfs:
// in the requesting ELF's RUNPATH/RPATH ($ORIGIN expanded, read as rootfs
// paths) or in the standard directories.
func (c *rootfsCloser) presentInRootfs(soname string, dirs []string) bool {
	for _, d := range dirs {
		p, err := resolveIn(c.root, filepath.Join(d, soname), true, false)
		if err != nil {
			continue
		}
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func (c *rootfsCloser) searchDirs(f *elf.File, self string) []string {
	var dirs []string
	origin, _ := filepath.Rel(c.root, filepath.Dir(self))
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		vals, _ := f.DynString(tag)
		for _, v := range vals {
			for _, e := range strings.Split(v, ":") {
				e = strings.ReplaceAll(strings.ReplaceAll(e, "${ORIGIN}", origin), "$ORIGIN", origin)
				if e = strings.TrimPrefix(e, "/"); e != "" {
					dirs = append(dirs, e)
				}
			}
		}
	}
	return append(dirs, libSearchDirs...)
}

// findInDeps returns the real path of a regular file named soname in a
// dependency prefix, or "". A candidate that escapes its prefix is refused.
func (c *rootfsCloser) findInDeps(soname string) string {
	for _, dep := range c.deps {
		for _, d := range libSearchDirs {
			p, err := resolveIn(dep, filepath.Join(d, soname), false, false)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					c.refused = append(c.refused, fmt.Sprintf("%s: %v", soname, err))
				}
				continue
			}
			if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

func (c *rootfsCloser) refusedNote(soname string) string {
	var out []string
	for _, r := range c.refused {
		if strings.HasPrefix(r, soname+": ") {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " (refused: " + strings.Join(out, "; ") + ")"
}

// provide makes soname present in the rootfs, copying it from a dependency
// when needed. It reports whether the name is now (or already was) available.
func (c *rootfsCloser) provide(soname string, dirs []string, depth int) (bool, error) {
	if !validSoname(soname) {
		return false, nil
	}
	if c.presentInRootfs(soname, dirs) {
		return true, nil
	}
	src := c.findInDeps(soname)
	if src == "" {
		return false, nil
	}
	dst, err := c.install(src, soname)
	if err != nil {
		return false, err
	}
	return true, c.enqueue(dst, depth+1)
}

// install copies src (a regular file) into the rootfs lib dir under its own
// name, and adds soname as a sibling symlink when the names differ. It returns
// the path of the copied file.
// ensureDir resolves rel inside the rootfs and creates it. The resolved path
// has every symlink already followed, so MkdirAll cannot be sent elsewhere.
func (c *rootfsCloser) ensureDir(rel string) (string, error) {
	dir, err := resolveIn(c.root, rel, true, true)
	if err != nil {
		return "", fmt.Errorf("rootfs: %s: %w", rel, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("rootfs: %s: %w", rel, err)
	}
	return dir, nil
}

func (c *rootfsCloser) install(src, soname string) (string, error) {
	if len(c.copied) >= maxRootfsLibs {
		return "", fmt.Errorf("rootfs: more than %d libraries to copy", maxRootfsLibs)
	}
	dir, err := c.ensureDir(rootfsLibDir)
	if err != nil {
		return "", err
	}
	real := filepath.Base(src)
	dst := filepath.Join(dir, real)
	if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
		if err := copyBounded(src, dst); err != nil {
			return "", err
		}
		c.logf("rootfs: copied %s from %s", real, filepath.Dir(src))
	} else if err != nil {
		return "", err
	}
	if real != soname {
		link := filepath.Join(dir, soname)
		if _, err := os.Lstat(link); errors.Is(err, fs.ErrNotExist) {
			if err := os.Symlink(real, link); err != nil {
				return "", err
			}
		}
	}
	for _, n := range []string{real, soname} {
		if !c.copied[n] {
			c.copied[n] = true
			c.report.Copied = append(c.report.Copied, n)
		}
	}
	return dst, nil
}

func copyBounded(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxLibBytes {
		return fmt.Errorf("rootfs: %s is not a regular file of at most %d bytes", src, maxLibBytes)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm()|0o200)
	if err != nil {
		return err
	}
	if _, err := ioCopy(out, io.LimitReader(in, maxLibBytes)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (c *rootfsCloser) examine(q queued) error {
	f, err := elf.Open(q.path)
	if err != nil {
		c.fail("%s: not a readable ELF: %v", c.rel(q.path), err)
		return nil
	}
	defer f.Close()
	c.report.ELFs++
	name := c.rel(q.path)
	dirs := c.searchDirs(f, q.path)

	needed, _ := f.ImportedLibraries()
	for _, n := range needed {
		ok, err := c.provide(n, dirs, q.depth)
		if err != nil {
			return err
		}
		if !ok {
			c.fail("%s: DT_NEEDED %q not found in the rootfs or in any dependency prefix%s", name, n, c.refusedNote(n))
		}
	}

	if err := c.interp(f, name, q.depth); err != nil {
		return err
	}

	sec := f.Section(dlopenSection)
	if sec == nil || sec.Type != elf.SHT_NOTE {
		return nil
	}
	if sec.Size > maxDlopenBytes {
		c.fail("%s: %s is %d bytes, over the %d limit", name, dlopenSection, sec.Size, maxDlopenBytes)
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		c.fail("%s: %s unreadable: %v", name, dlopenSection, err)
		return nil
	}
	entries, err := ParseDlopenNotes(data, f.ByteOrder)
	if err != nil {
		c.fail("%s: %v", name, err)
		return nil
	}
	for _, e := range entries {
		got := false
		for _, s := range e.Sonames {
			ok, err := c.provide(s, dirs, q.depth)
			if err != nil {
				return err
			}
			if ok {
				got = true
				break
			}
		}
		if got {
			continue
		}
		if e.Priority == PriorityRequired {
			c.fail("%s: dlopen entry (feature %q, priority required) has none of %q available", name, e.Feature, e.Sonames)
			continue
		}
		c.report.Misses = append(c.report.Misses, RootfsMiss{Priority: e.Priority, Feature: e.Feature, Sonames: e.Sonames, Needer: name})
		c.logf("rootfs: miss: %s dlopen %q (feature %q) needed by %s", e.Priority, e.Sonames, e.Feature, name)
	}
	return nil
}

// interp makes PT_INTERP resolve inside the rootfs: the loader is copied like a
// library, and linked at the path the binary names when that is elsewhere.
func (c *rootfsCloser) interp(f *elf.File, name string, depth int) error {
	var ip string
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if p.Filesz > maxInterpBytes {
			c.fail("%s: PT_INTERP of %d bytes", name, p.Filesz)
			return nil
		}
		b := make([]byte, p.Filesz)
		if _, err := io.ReadFull(p.Open(), b); err != nil {
			c.fail("%s: PT_INTERP unreadable: %v", name, err)
			return nil
		}
		ip = strings.TrimRight(string(b), "\x00")
		break
	}
	if ip == "" {
		return nil
	}
	if !strings.HasPrefix(ip, "/") || strings.ContainsRune(ip, 0) {
		c.fail("%s: PT_INTERP %q is not an absolute path", name, ip)
		return nil
	}
	if p, err := resolveIn(c.root, ip, true, false); err == nil {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			return nil
		}
	}
	base := filepath.Base(ip)
	if !validSoname(base) {
		c.fail("%s: PT_INTERP %q has no usable name", name, ip)
		return nil
	}
	src := c.findInDeps(base)
	if src == "" {
		c.fail("%s: dynamic loader %s not found in the rootfs or in any dependency prefix (is glibc in the closure?)%s", name, ip, c.refusedNote(base))
		return nil
	}
	dst, err := c.install(src, base)
	if err != nil {
		return err
	}
	// Link the path the binary names to the copy, relative so it stays inside.
	parent, err := c.ensureDir(filepath.Dir(ip))
	if err != nil {
		return err
	}
	link := filepath.Join(parent, base)
	if link != dst {
		if _, err := os.Lstat(link); errors.Is(err, fs.ErrNotExist) {
			target, _ := filepath.Rel(parent, dst) // both are under root: Rel cannot fail
			if err := os.Symlink(target, link); err != nil {
				return err
			}
		}
	}
	return c.enqueue(dst, depth+1)
}
