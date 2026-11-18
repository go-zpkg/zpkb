package target

import (
	"strings"
	"testing"
)

// ⛔⛔ THE CONTROL THAT MATTERS MOST: every slug spelled today must be spelled
// identically tomorrow. Every artifact published so far lives at
// `<project>/<os>/<arch>/…`, and a libc component appended unconditionally
// would move all of them for a value no existing bottle records.
func TestAnUnnamedLibcChangesNoSlug(t *testing.T) {
	for _, tc := range []Target{
		{Platform: "linux", Arch: "x86-64"},
		{Platform: "linux", Arch: "aarch64"},
		{Platform: "linux", Arch: "s390x"},
		{Platform: "darwin", Arch: "aarch64"},
		{Platform: "windows", Arch: "x86-64"},
		{Platform: "wasip1", Arch: "wasm"},
		{Platform: "freebsd", Arch: "x86-64"},
	} {
		want := tc.Platform + "/" + tc.Arch
		if got := tc.Slug(); got != want {
			t.Errorf("Slug() = %q, want %q — a published path moved", got, want)
		}
	}
}

func TestANamedLibcSpellsItself(t *testing.T) {
	tgt := Target{Platform: "linux", Arch: "x86-64", Libc: "musl"}
	if got := tgt.Slug(); got != "linux-musl/x86-64" {
		t.Errorf("Slug() = %q, want linux-musl/x86-64", got)
	}
}

func TestOverrideReadsTheLibc(t *testing.T) {
	for _, tc := range []struct{ raw, platform, libc, arch string }{
		{"linux-musl/x86-64", "linux", "musl", "x86-64"},
		{"linux-musl+x86-64", "linux", "musl", "x86-64"},
		{"linux-gnu/aarch64", "linux", "gnu", "aarch64"},
		// No libc named: every spelling in use today.
		{"linux/x86-64", "linux", "", "x86-64"},
		{"windows/x86-64", "windows", "", "x86-64"},
		{"wasip1/wasm", "wasip1", "", "wasm"},
	} {
		t.Setenv("ZPKB_TARGET", tc.raw)
		p, a, l, ok, err := Override()
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", tc.raw, ok, err)
		}
		if p != tc.platform || a != tc.arch || l != tc.libc {
			t.Errorf("%s → platform=%q arch=%q libc=%q, want %q/%q/%q",
				tc.raw, p, a, l, tc.platform, tc.arch, tc.libc)
		}
	}
}

// ⛔ A libc this factory cannot build is refused for THE LIBC, not for the
// arch. A refusal that reports the wrong half sends the reader to the wrong
// file — the same reason the arch refusal names pkgx's spelling.
func TestAnUnbuildableLibcIsRefusedForTheRightReason(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		// bionic is deliberately absent from the table: it needs the NDK's
		// toolchain and sysroot, so accepting the name would let a factory
		// that cannot build it be asked to.
		{"linux-bionic/aarch64", "unsupported libc"},
		{"linux-uclibc/x86-64", "unsupported libc"},
		// darwin names no libc at all, and the refusal says which platform does.
		{"darwin-musl/aarch64", "names no C library"},
	} {
		t.Setenv("ZPKB_TARGET", tc.raw)
		_, _, _, _, err := Override()
		if err == nil {
			t.Fatalf("%s was accepted", tc.raw)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s → %v, want it to mention %q", tc.raw, err, tc.want)
		}
	}
}

// ⚠ The arch is still checked, and a bad arch beside a good libc must fail on
// the arch — otherwise the libc check would be shadowing it.
func TestAGoodLibcDoesNotExcuseABadArch(t *testing.T) {
	t.Setenv("ZPKB_TARGET", "linux-musl/wasm")
	_, _, _, _, err := Override()
	if err == nil {
		t.Fatal("linux-musl/wasm was accepted")
	}
	if !strings.Contains(err.Error(), "arch") {
		t.Errorf("got %v, want an arch refusal", err)
	}
}

func TestResolveCarriesTheLibc(t *testing.T) {
	t.Setenv("ZPKB_TARGET", "linux-musl/x86-64")
	tgt, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Libc != "musl" || tgt.Slug() != "linux-musl/x86-64" {
		t.Errorf("Resolve() = %+v, want Libc=musl and the matching slug", tgt)
	}
}

// ⛔⛔ Host() MUST NOT CLAIM A LIBC IT HAS NOT LOOKED FOR. Answering "gnu"
// would be an assumption wearing a measurement's clothes: a native build on a
// musl machine would then publish a bottle labelled gnu. Empty means
// "unrecorded", which is this factory's actual state.
func TestHostNamesNoLibc(t *testing.T) {
	if got := Host().Libc; got != "" {
		t.Errorf("Host().Libc = %q, want empty — nothing here has looked at the host's libc", got)
	}
}

// ⛔ OSDir AND Slug MUST NOT BE TWO RULES. Five call sites spell the target
// into a path or an identity, and they are only consistent because they share
// this one component; a Slug that stopped agreeing with OSDir would make the
// artifact path and the published identity disagree about the same build.
func TestOSDirIsTheOSHalfOfTheSlug(t *testing.T) {
	for _, tgt := range []Target{
		{Platform: "linux", Arch: "x86-64"},
		{Platform: "linux", Arch: "x86-64", Libc: "musl"},
		{Platform: "linux", Arch: "aarch64", Libc: "gnu"},
		{Platform: "darwin", Arch: "aarch64"},
		{Platform: "wasip1", Arch: "wasm"},
	} {
		if got, want := tgt.Slug(), tgt.OSDir()+"/"+tgt.Arch; got != want {
			t.Errorf("Slug() = %q but OSDir()+/+Arch = %q", got, want)
		}
	}
	if got := (Target{Platform: "linux", Arch: "x86-64"}).OSDir(); got != "linux" {
		t.Errorf("OSDir() = %q, want linux — an unnamed libc adds nothing", got)
	}
	if got := (Target{Platform: "linux", Arch: "x86-64", Libc: "musl"}).OSDir(); got != "linux-musl" {
		t.Errorf("OSDir() = %q, want linux-musl", got)
	}
}

// ⛔ LibcProject IS EXERCISED HERE AND NOT ONLY FROM `build`. Its only caller
// is in another package, so the coverage gate — which is per package — saw
// 0.0% and went red. That is the gate working: an exported function whose own
// package never calls it is a function whose contract nothing local pins, and
// the contract here is the second return value.
func TestLibcProjectNamesAProjectOrRefuses(t *testing.T) {
	for _, tc := range []struct{ libc, want string }{
		{"", "gnu.org/glibc"},
		{"gnu", "gnu.org/glibc"},
		{"musl", "musl.libc.org"},
	} {
		got, ok := LibcProject(tc.libc)
		if !ok || got != tc.want {
			t.Errorf("LibcProject(%q) = %q, %v; want %q, true", tc.libc, got, ok, tc.want)
		}
	}
	// ⛔ AND THE MISS RETURNS false WITH AN EMPTY STRING, never a plausible
	// project. bionic is in the table's own comment as deliberately absent, so
	// it is the honest probe: a caller that wrote "" into a published
	// dependency would publish a dependency on a project called "".
	for _, bad := range []string{"bionic", "uclibc", "llvm", "GNU"} {
		if got, ok := LibcProject(bad); ok || got != "" {
			t.Errorf("LibcProject(%q) = %q, %v; want \"\", false", bad, got, ok)
		}
	}
}

// ⭐ AND EVERY LIBC THE TABLES ACCEPT MUST HAVE A PROJECT. The two tables are
// written apart — `platformLibcs` says what a target may NAME, `libcProjects`
// says what provides it — so a name added to one and not the other would be
// accepted by Override() and then refused at identity time, which is a failure
// after the build rather than before it.
func TestEveryAcceptedLibcHasAProject(t *testing.T) {
	for _, p := range libcPlatforms() {
		for _, l := range Libcs(p) {
			if _, ok := LibcProject(l); !ok {
				t.Errorf("%s accepts libc %q, but no project provides it", p, l)
			}
		}
	}
	// The other direction is NOT asserted: `libcProjects` carries "" for the
	// unnamed case, which is not a name any platform lists.
}

func TestIsLibcAndLibcs(t *testing.T) {
	if !IsLibc("linux", "") || !IsLibc("darwin", "") {
		t.Error("an unnamed libc must be valid everywhere")
	}
	if !IsLibc("linux", "musl") || !IsLibc("linux", "gnu") {
		t.Error("linux names gnu and musl")
	}
	if IsLibc("linux", "bionic") {
		t.Error("bionic is deliberately absent until the NDK toolchain exists")
	}
	if got := strings.Join(Libcs("linux"), ","); got != "gnu,musl" {
		t.Errorf("Libcs(linux) = %q, want gnu,musl", got)
	}
	if len(Libcs("darwin")) != 0 {
		t.Error("darwin names no libc")
	}
}
