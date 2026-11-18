// Package target is the single source of truth for the *target* platform/arch
// of a build.
//
// brewkit is historically a *native* build tool: everything pivots on the host
// == the machine it runs on == the thing it builds for. To cross-compile
// (notably Windows PE artifacts built on a linux/darwin host) we split "where am
// I running" (Host) from "what am I building for" (Target). Only OUTPUT/target
// decisions consult Target:
//
//   - the `if:` guards in a recipe's build/test script
//   - platform-keyed env selection
//   - fix-up (POSIX relocation) selection
//   - the artifact slug (platform-key)
//
// Shell-environment decisions ("which TMPDIR does *this* host use") keep using
// Host. The target is taken from (first match wins):
//
//  1. the ZPKB_TARGET env var  (eg. "windows/x86-64" or "windows+x86-64")
//  2. Host()  (native build — byte-for-byte unchanged behaviour)
package target

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Target is the resolved build target.
type Target struct {
	Platform string // darwin | linux | windows | wasip1
	Arch     string // x86-64 | aarch64 | s390x | wasm (wasip1 only)
	// Triple is the compiler triple — and for every target but windows it is
	// the triple of the machine bk RUNS ON, not the one named here.
	//
	//	$ ZPKB_TARGET=linux/s390x bk target        # on a Mac
	//	linux/s390x triple=aarch64-apple-darwin cross=true
	//
	// That is correct today and reads as a bug, which is why it is written
	// down rather than left to be rediscovered. bk cross-compiles to windows
	// and nowhere else: a unix target is always built natively or under
	// emulation, so host and target coincide and the value is right. The
	// windows branch of Resolve computes a real cross triple because windows
	// is the case where they differ.
	//
	// It matters because the value does not stay here. It names the compiler
	// shims autoconf probes for, and it reaches every recipe as {{hw.target}}
	// — a name that promises the target. A recipe author reading that name
	// will believe it, and one of ours did: rust-lang.org/cargo picks its
	// bootstrap archive by this triple, which is right only while the two
	// coincide, and the comment there says so.
	//
	// A unix→unix cross build would need this computed from Platform/Arch.
	// Changing it before then is a fix to a case that cannot arise, and the
	// test below pins the current answer deliberately.
	Triple string

	// Libc names the C library a linux target is built against: "gnu", "musl".
	// It is EMPTY everywhere else, and empty on linux means "whatever the host
	// has, unrecorded" — which is this factory's actual state and not a
	// default standing in for one.
	//
	// ⛔ THE FIELD EXISTS BECAUSE THE LIBC WAS NOT IN THE GRAPH AT ALL.
	// Measured 2026-11-18 over go-zpkg/recipes' 247 recipes: exactly ONE names
	// a libc — go-zpkg/base-toolchain, as `"gnu.org/glibc" = "*"`, with no
	// version constraint — and no ordinary recipe names one. The libc arrived
	// because the base toolchain is prepended, so there was no edge to vary
	// and several libcs were not expressible (go-zpkg/packages#475).
	//
	// ⚠ A LIBC IS NOT AN ORDINARY DEPENDENCY, which is why it lives here and
	// not in a recipe. Every object in a closure must agree on it: a bottle
	// built against musl cannot be loaded beside one built against glibc. So
	// it is part of the target's IDENTITY, as in Rust's
	// x86_64-unknown-linux-musl beside -gnu, Zig's triples, and Alpine against
	// Debian — every system that ships binaries puts it in the name, because
	// the artifacts are not interchangeable. Modelling it as a dependency to
	// be solved (Spack's virtual providers) suits a from-source, per-site
	// builder and not a publisher of bottles: a mixed closure is not a
	// resolution error to report, it is an artifact that cannot exist.
	//
	// ⛔ AND THIS FIELD ALONE DOES NOT RECORD WHAT A NATIVE BUILD USED. Host()
	// leaves it empty rather than answering "gnu", because nothing here has
	// looked: that would be an assumption wearing a measurement's clothes, and
	// a native build on a musl machine would then publish a bottle labelled
	// gnu. Detecting the host's libc, and recording the answer on the bottle,
	// is go-zpkg/packages#475's later work and go-zpkg/packages#225 step 5.
	// What this field buys today is that the choice can be NAMED.
	Libc string
}

// Cross reports whether Platform/Arch differ from the running host.
func (t Target) Cross() bool {
	h := Host()
	return t.Platform != h.Platform || t.Arch != h.Arch
}

// Slug is the artifact platform key, eg. "linux/x86-64", "linux-musl/x86-64".
//
// ⭐ THE LIBC APPEARS ONLY WHEN IT WAS NAMED, and that is a compatibility
// decision rather than an oversight. Every artifact published so far lives at
// `<project>/<os>/<arch>/…`; appending a libc component unconditionally would
// move all of them, for a value no existing bottle records. An empty Libc
// therefore spells exactly what it spells today, and a named one — the only
// way to get a non-glibc build — spells itself.
//
// ⚠ The consequence, stated rather than discovered later: a native glibc build
// and a native musl build both still produce "linux/x86-64" and would collide
// on that path. Making them distinct needs Host() to know which libc it is on,
// which is go-zpkg/packages#475's later work. This function makes the
// distinction WRITABLE; it does not yet make it automatic.
func (t Target) Slug() string {
	if t.Libc == "" {
		return t.Platform + "/" + t.Arch
	}
	return t.Platform + "-" + t.Libc + "/" + t.Arch
}

var (
	// platformArches is the table of what bk can build FOR: platform -> arches.
	// Arch validity is per platform, because wasm is an architecture only of
	// wasip1 and `linux/wasm` or `wasip1/x86-64` name no machine at all.
	//
	// wasip1 is GOOS=wasip1 GOARCH=wasm: pure-Go builds (CGO_ENABLED=0) that
	// produce a .wasm module, published as OCI platform os=wasip1
	// architecture=wasm. C toolchains (wasi-sdk) are not part of this target.
	platformArches = map[string]map[string]bool{
		// s390x joined the unix list when a LinuxONE runner came online. An arch
		// with no machine behind it is a guess, and this is the one place that
		// should not hold one.
		//
		// Host() has never had a list -- it passes GOARCH through pkgxArch -- so
		// until now the same architecture was legal natively and refused the
		// moment a build NAMED it. That asymmetry is how `--platform linux/s390x`
		// reached
		//
		//	factory: unsupported target arch: "s390x"
		//
		// on a runner that had already checked the repo out and installed bk.
		"darwin":  {"x86-64": true, "aarch64": true, "s390x": true},
		"linux":   {"x86-64": true, "aarch64": true, "s390x": true},
		"windows": {"x86-64": true, "aarch64": true, "s390x": true},
		"wasip1":  {"wasm": true},
		// ⛔ THE BSDs ARE x86-64 ONLY, FOR THE REASON THIS MAP EXISTS. The
		// machine behind them is the `vmactions/{freebsd,netbsd,openbsd}-vm`
		// qemu guest that go-zpkg/pkgm already runs its tests in, and those
		// actions offer amd64 and nothing else. aarch64 joins the day there is
		// a machine, exactly as s390x did — adding it now would put a guess in
		// the one place that must not hold one.
		//
		// `artifact` has known these three since before any artifact existed for
		// them (host.go, pkgx.go's platform slugs), and says so on purpose:
		// "no artifact for <project> (freebsd/aarch64)". So the consumer side
		// was ready and the FACTORY was the gap.
		"freebsd": {"x86-64": true},
		"openbsd": {"x86-64": true},
		"netbsd":  {"x86-64": true},
	}
	// llvm.org/mingw-w64 cross triples (see the go-zpkg/packages Windows
	// factories: x86_64-w64-mingw32-clang / aarch64-w64-mingw32-clang).
	windowsTriples = map[string]string{
		"x86-64":  "x86_64-w64-mingw32",
		"aarch64": "aarch64-w64-mingw32",
	}
	// platformLibcs is what a platform's C library may be NAMED as. It exists
	// for the same reason platformArches does: a value with no machine behind
	// it is a guess, and this is one of the two places that must not hold one.
	//
	// ⛔ ONLY LINUX HAS AN ENTRY, and that is a fact about the other platforms
	// rather than a gap here. darwin's libSystem, the three BSDs' libcs and
	// windows' CRT are not choices a build makes — there is one per platform
	// and naming it would add a component that can take exactly one value.
	//
	// ⛔ AND BIONIC IS DELIBERATELY ABSENT. Android's libc is reachable only
	// through the NDK's toolchain and sysroot: it is a cross-compilation
	// target, not a libc that can be swapped under a native build, so it needs
	// the toolchain work before the name means anything. Adding it here now
	// would let `ZPKB_TARGET=linux-bionic/aarch64` be accepted by a factory
	// that cannot build it — the asymmetry platformArches' own comment records
	// s390x having had.
	platformLibcs = map[string]map[string]bool{
		"linux": {"gnu": true, "musl": true},
	}
	// overrideRE accepts an optional libc on the platform component:
	// `linux/x86-64`, `linux-musl/x86-64`, `linux-musl+x86-64`.
	overrideRE = regexp.MustCompile(`^([a-z0-9_]+)(?:-([a-z0-9]+))?[/+]([a-z0-9-]+)$`)
)

// IsLibc reports whether platform/libc names a C library this factory can be
// targeted at. An empty libc is always valid: it means "unnamed", which every
// platform allows and which is what every target spelled today carries.
func IsLibc(platform, libc string) bool {
	if libc == "" {
		return true
	}
	return platformLibcs[platform][libc]
}

// Libcs lists the C libraries a platform may name, sorted, for an error
// message that must not restate the table.
func Libcs(platform string) []string {
	out := make([]string, 0, len(platformLibcs[platform]))
	for l := range platformLibcs[platform] {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// wasip1Triple is the LLVM name of the Go wasip1/wasm target (Go's GOOS=wasip1
// GOARCH=wasm; WASI preview 1 on a 32-bit wasm machine).
const wasip1Triple = "wasm32-wasip1"

// zpkgArch maps a Go GOARCH to the arch naming this project's catalogue and
// artifacts use ("x86-64", "aarch64").
//
// ⛔ IT WAS CALLED pkgxArch, AND THE COMMENT SAID "pkgx's arch naming". That
// was true while the fork tracked upstream and is not any more: the direct
// filiation is broken and this project is no longer compatible with pkgx
// (go-zpkg/packages#431). The spellings are OURS now, and a name saying
// otherwise points a reader at a compatibility that does not exist.
func zpkgArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "aarch64"
	default:
		return goarch
	}
}

// nativeTriple is a best-effort native compiler triple for the running host.
func nativeTriple() string { return nativeTripleFor(runtime.GOOS, runtime.GOARCH) }

// nativeTripleFor is the pure, testable core of nativeTriple.
func nativeTripleFor(goos, goarch string) string {
	arch := goarch
	switch goarch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}
	switch goos {
	case "wasip1":
		return wasip1Triple
	case "darwin":
		return arch + "-apple-darwin"
	case "windows":
		return arch + "-w64-mingw32"
	case "freebsd", "openbsd", "netbsd":
		// ⛔ THE DEFAULT BELOW WOULD CALL A BSD HOST "linux-gnu". These builds
		// are NATIVE — the compiler runs inside the BSD guest — so the triple
		// is what that guest's clang already calls itself, and handing it
		// `x86_64-unknown-linux-gnu` is how a native build acquires a cross
		// build's problems for no reason.
		return arch + "-unknown-" + goos
	default:
		return arch + "-unknown-linux-gnu"
	}
}

// Host is the platform/arch/triple of the machine bk is running on.
// IsPlatform and IsArch are the ONE vocabulary of platform names.
//
// There were two. buildscript kept its own `platforms`/`arches` maps to
// decide what a recipe's `env: {aarch64: …}` key and its `if: linux/x86-64`
// guard mean, and when s390x was added here that copy was not. The
// consequences were silent in both directions: an `env` keyed by s390x
// became a literal variable of that name, and a step guarded `if: s390x`
// ran on EVERY platform, because matchGuard lets an unrecognised condition
// through rather than dropping the step.
//
// Predicates rather than the maps, so a caller cannot hold a reference and
// drift again.
func IsPlatform(s string) bool { _, ok := platformArches[s]; return ok }

// IsArch reports whether s is an architecture this factory builds for on SOME
// platform, in pkgx's spelling (`x86-64`, not `amd64` — see pkgxArch). It is
// the recipe vocabulary (`env: {wasm: …}`); whether a given platform/arch PAIR
// is buildable is IsPair.
func IsArch(s string) bool {
	for _, arches := range platformArches {
		if arches[s] {
			return true
		}
	}
	return false
}

// IsPair reports whether platform/arch names a machine bk can build for:
// `wasip1/wasm` and `linux/x86-64` do, `linux/wasm` and `wasip1/x86-64` do not.
func IsPair(platform, arch string) bool { return platformArches[platform][arch] }

// Platforms and Arches list the vocabulary, sorted, for callers that need a
// set (a recipe-key regexp) and must not restate it.
func Platforms() []string {
	out := make([]string, 0, len(platformArches))
	for p := range platformArches {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Arches is the sorted union of every platform's arches.
func Arches() []string {
	seen := map[string]bool{}
	for _, arches := range platformArches {
		for a := range arches {
			seen[a] = true
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func Host() Target {
	p := runtime.GOOS
	return Target{Platform: p, Arch: zpkgArch(runtime.GOARCH), Triple: nativeTriple()}
}

// Override parses & validates ZPKB_TARGET, returning ok=false when unset.
// It returns an error for a malformed or unsupported value.
//
// ⛔⛔ THE VARIABLE WAS `BREWKIT_TARGET`, AND NO ALIAS WAS KEPT. The command is
// `zpkb`; `BREWKIT_TARGET` is upstream brewkit's name, and upstream's brewkit can
// sit on the same PATH as ours — which is the entire reason the binaries were
// renamed. A variable read by both would be the same collision the rename
// existed to remove, left in the place that decides what a build targets.
//
// An alias would be worse than the old name alone: a tree with both set would
// take one of them by a precedence nobody could see, and every document would
// have to explain two spellings forever. The old name is simply not read, and
// `TestTheOldVariableNameIsNotRead` is the gate that says so — because "we
// removed it" is a claim about code that nothing was asserting.
//
// It is a breaking change, below v1, in the same release line as the binaries'
// own rename. Nothing in this organisation set it outside its own sources: the
// only other mentions were two recipe comments, two READMEs and one docs page,
// all updated with it.
func Override() (platform, arch, libc string, ok bool, err error) {
	raw := strings.TrimSpace(os.Getenv("ZPKB_TARGET"))
	if raw == "" {
		return "", "", "", false, nil
	}
	m := overrideRE.FindStringSubmatch(raw)
	if m == nil {
		return "", "", "", false, fmt.Errorf("invalid ZPKB_TARGET: %q (expected eg. 'windows/x86-64' or 'linux-musl/x86-64')", raw)
	}
	platform, libc, arch = m[1], m[2], m[3]
	if !IsPlatform(platform) {
		return "", "", "", false, fmt.Errorf("unsupported target platform: %q", platform)
	}
	// ⛔ ASKED BEFORE THE ARCH, so `linux-bionic/aarch64` is refused for the
	// libc it names rather than passing because the arch is fine. A refusal
	// that reports the wrong half sends the reader to the wrong file.
	if !IsLibc(platform, libc) {
		if len(platformLibcs[platform]) == 0 {
			return "", "", "", false, fmt.Errorf("platform %q names no C library (only %s does)", platform, strings.Join(libcPlatforms(), ", "))
		}
		return "", "", "", false, fmt.Errorf("unsupported libc %q for platform %q (this factory builds %s)", libc, platform, strings.Join(Libcs(platform), ", "))
	}
	if !IsPair(platform, arch) {
		// amd64 and arm64 are Go's spellings for two of these machines and the
		// mistake actually made, since every other arch name here is shared.
		// Refusing without saying so sends the reader looking for a missing
		// port rather than at the two characters that differ.
		if zpkx := zpkgArch(arch); zpkx != arch && IsPair(platform, zpkx) {
			return "", "", "", false, fmt.Errorf("unsupported target arch: %q (pkgx spells it %q)", arch, zpkx)
		}
		return "", "", "", false, fmt.Errorf("unsupported target arch %q for platform %q", arch, platform)
	}
	return platform, arch, libc, true, nil
}

// libcPlatforms lists the platforms that name a C library at all, read from
// the table rather than restated.
func libcPlatforms() []string {
	out := make([]string, 0, len(platformLibcs))
	for p := range platformLibcs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// IsCross reports whether a ZPKB_TARGET override is set (a cross build).
func IsCross() (bool, error) {
	_, _, _, ok, err := Override()
	return ok, err
}

// Resolve returns the build target, falling back to Host() for native builds.
func Resolve() (Target, error) {
	platform, arch, libc, ok, err := Override()
	if err != nil {
		return Target{}, err
	}
	if !ok {
		return Host(), nil
	}
	triple := nativeTriple()
	if platform == "wasip1" {
		// Like windows, a real cross triple: the module is never the machine
		// bk runs on.
		triple = wasip1Triple
	}
	if platform == "windows" {
		// This used to read `triple = windowsTriples[arch]` under a comment
		// saying every supported arch had an entry, so the lookup was total.
		// Widening supportedArches ended that, and a map miss does not fail:
		// it yields "", and a build carries an empty triple to whichever step
		// first needs a compiler, which is a long way from here.
		t, ok := windowsTriples[arch]
		if !ok {
			return Target{}, fmt.Errorf("no windows cross triple for arch %q (llvm-mingw targets %s)", arch, tripleArches())
		}
		triple = t
	}
	// ⚠ THE TRIPLE IS NOT RECOMPUTED FROM THE LIBC, and that is deliberate
	// while it stays the HOST's triple (see Target.Triple). A musl target
	// needs `x86_64-unknown-linux-musl` there, and producing it means the
	// unix→unix cross build the comment above says does not arise yet — the
	// toolchain work in go-zpkg/packages#475. Writing it now would make the
	// field claim a cross compiler this factory has not built.
	return Target{Platform: platform, Arch: arch, Libc: libc, Triple: triple}, nil
}

// tripleArches lists the arches llvm-mingw can be targeted at, for the error
// above. Read from the table rather than restated, so it cannot describe a
// table it no longer matches.
func tripleArches() string {
	out := make([]string, 0, len(windowsTriples))
	for a := range windowsTriples {
		out = append(out, a)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
