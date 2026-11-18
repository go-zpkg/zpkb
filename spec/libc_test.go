package spec

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// ⛔⛔ A LOCK MUST NOT PIN A CLOSURE THAT TWO DIFFERENT WORLDS BOTH SATISFY.
//
// The hash covers "the project as resolved", and which C library it resolved
// against is part of that: a glibc closure and a musl closure are not the same
// resolution, and `lock --check` comparing them would report "unchanged" for a
// build that cannot even load.
func TestTheSpecHashSeparatesTheLibcs(t *testing.T) {
	rec := &pantry.Recipe{Versions: map[string]any{"github": "a/b/tags"}}
	hash := func(tgt target.Target) string {
		t.Helper()
		h, err := Hash(DomainLock, []*pantry.Recipe{rec}, "acme.org/tool", "1.2.3", tgt, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	glibc := hash(target.Target{Platform: "linux", Arch: "x86-64", Libc: "gnu"})
	musl := hash(target.Target{Platform: "linux", Arch: "x86-64", Libc: "musl"})
	if glibc == musl {
		t.Error("glibc and musl hash alike — a lock could not tell the two apart")
	}

	// ⭐ THE CONTROL, AND IT IS THE REASON THIS CHANGE IS SAFE AT ALL: an
	// unnamed libc must hash to what the old `Platform + "/" + Arch` form
	// hashed to, byte for byte. DomainLock is frozen into every lock file ever
	// written; a component appended unconditionally would invalidate all of
	// them, and `lock --check` would report the whole pantry as changed.
	//
	// The literal that pins the VALUE lives beside specHash in cmd/zpkb
	// (TestTheLockSpecHashIsTheValueLockFilesHold). This asserts the shape of
	// the equality here, where the format is written.
	unnamed := hash(target.Target{Platform: "linux", Arch: "x86-64"})
	if unnamed == glibc || unnamed == musl {
		t.Error("an unnamed libc collides with a named one; it must be its own, older, value")
	}
}

// ⚠ AND THE PLATFORM STILL SEPARATES. A libc term that somehow replaced the
// platform rather than extending it would pass the test above and break
// everything else, so the older property is re-asserted beside the new one.
func TestThePlatformStillSeparatesWithALibcNamed(t *testing.T) {
	rec := &pantry.Recipe{Versions: map[string]any{"github": "a/b/tags"}}
	hash := func(tgt target.Target) string {
		t.Helper()
		h, err := Hash(DomainLock, []*pantry.Recipe{rec}, "p", "1", tgt, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a := hash(target.Target{Platform: "linux", Arch: "x86-64", Libc: "musl"})
	b := hash(target.Target{Platform: "linux", Arch: "aarch64", Libc: "musl"})
	if a == b {
		t.Error("two arches of the same libc hash alike")
	}
}
