package build

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// concreteOf describes what this build IS, in the form the artifact carries and
// a reader can verify: `artifact.Concrete`.
//
// ⛔⛔ THERE IS ONE DEFINITION OF A BUILD'S IDENTITY AND IT LIVES IN `artifact`.
// This function used to compute a second one, `spec.Hash(spec.DomainBuild,…)`,
// and put its short form in the install prefix. That was wrong in a way that
// would only have surfaced after publishing: `artifact.VerifySpec` checks that
// the spec on a manifest hashes to the hash in the tag, so a tag carrying our
// number and an annotation carrying artifact's would have made every artifact we
// publish fail its own verification — and the message says "the artifact does
// not match its own description", which reads as tampering.
//
// It was also the weaker of the two. A hash is only worth what a reader can
// recompute, and nothing published carries the inputs to `spec.Hash`: the
// annotation holds the platform, the resolved closure and a recipe DIGEST, so
// `Concrete.Hash()` can be recomputed from the artifact and ours could not.
// `spec` remains what it was written for, `zpkb lock`, whose domain string is
// frozen into every lock file in existence.
//
// ⛔ DEPENDENCIES ARE IDENTIFIED BY THEIR OWN HASH, WHICH MAKES THIS MERKLE.
// The hash comes out of the resolved prefix — `…/openssl.org/v3.6.4-h<hash>`
// — so hashing the edge carries the dependency's whole identity with it,
// transitively, the way a Nix derivation references its inputs by store path.
// A dependency still installed at an unhashed `v<version>` contributes an
// empty hash: that edge degrades to version-level precision and no further,
// and it repairs itself as the registry is rebuilt. Said out loud rather than
// hidden, because a hash is only as sharp as what it is taken over.
// ⛔⛔ THE LIBC THE BUILD LINKS AGAINST IS AN ARGUMENT HERE BECAUSE IT IS NOT
// IN `deps`. `--libc zpkx` and `--glibc <v>` are per-run FLAGS: they append
// `"+gnu.org/glibc@<v>"` to the generated script's environment eval
// (buildscript/wrapper.go), which never passes through `recipe.Dependencies`
// and so never reaches `DepTokens`. MEASURED on 2026-11-18, three materially
// different builds of one recipe:
//
//	system libc     v1.2.3-hhhrjzyh2dk56y7tc
//	zpkx libc       v1.2.3-hhhrjzyh2dk56y7tc
//	zpkx @2.27.0    v1.2.3-hhhrjzyh2dk56y7tc
//
// One identity for three ABIs — which is go-zpkg/packages#225's own sentence,
// "promote the glibc input into a recorded property", as a live defect rather
// than a plan. It needed no musl to exist.
//
// ⭐ IT ENTERS AS AN ORDINARY DEPENDENCY, not as a new field, and that is the
// whole reason this is safe: `Concrete.Deps` is already in the published
// schema, so `artifact.VerifySpec` keeps working and a consumer recomputing
// the hash from the manifest now SEES the libc listed. A new field would have
// changed the schema in another repository and invalidated every artifact's
// verification at once.
//
// ⚠ WITH NO PIN THE VERSION IS LEFT EMPTY, AND THAT IS A STATED LIMIT RATHER
// THAN AN OVERSIGHT. `--libc zpkx` without `--glibc` means "newest at eval
// time", which is not knowable before the compiler runs — and the identity
// must be, since the prefix is baked into the binaries. So two zpkx builds
// either side of a glibc release still share an identity. That edge degrades
// to "the gnu.org/glibc artifact was used" and no further, exactly as an
// unhashed dependency prefix degrades to version-level precision above.
type libcChoice struct {
	Mode    string // Runner.LibcMode: "zpkx", or "" for the container's own
	Version string // Runner.Glibc: a pin like "2.27.0", or "" for newest
}

// libcDep returns the dependency this choice adds, and false when it adds
// none. ⛔ NOT ON darwin/windows/wasip1: wrapper.go injects the glibc only
// under `o.LibcZpkx && o.Target.Platform == "linux"`, so recording it anywhere
// else would make the identity claim a link that never happened.
//
// ⛔⛔ THE PROJECT COMES FROM THE TARGET'S LIBC, NOT FROM A LITERAL, and this
// fixes a defect the two halves created between them. go-zpkg/zpkb#502 made
// `ZPKB_TARGET=linux-musl/x86-64` expressible; go-zpkg/zpkb#504 made the libc
// choice part of the identity — by writing the string "gnu.org/glibc". So a
// musl target recorded a GLIBC dependency, and because `artifact.VerifySpec`
// recomputes the hash from that same manifest, the bottle would have VERIFIED
// while its own record was wrong about its ABI. A false record is worse than
// an absent one: the absent one is visibly absent.
//
// ⚠ A libc with no project is an ERROR rather than an omission. Returning
// false here would silently drop the libc from the identity — which is the
// state go-zpkg/zpkb#504 existed to end — so an unknown name travels as an
// error to the caller instead.
func (l libcChoice) libcDep(tgt target.Target) (artifact.Dep, bool, error) {
	if l.Mode != "zpkx" || tgt.Platform != "linux" {
		return artifact.Dep{}, false, nil
	}
	proj, ok := target.LibcProject(tgt.Libc)
	if !ok {
		return artifact.Dep{}, false, fmt.Errorf(
			"no project provides libc %q, so this build cannot record what it linked against", tgt.Libc)
	}
	return artifact.Dep{Project: proj, Version: l.Version}, true, nil
}

func concreteOf(recipe *pantry.Recipe, tgt target.Target, deps []moustache.Dep, libc libcChoice) (artifact.Concrete, error) {
	dig, err := recipeDigest(recipe)
	if err != nil {
		return artifact.Concrete{}, err
	}
	c := artifact.Concrete{
		// ⛔⛔ THIS IS THE PUBLISHED ABI KEY, so it is the one site where a
		// missing libc is unrecoverable. `artifact.VerifySpec` recomputes this
		// from the manifest, so whatever is omitted here is omitted from what a
		// consumer is able to check: a bottle built against musl and one built
		// against glibc would carry the SAME Platform and hash alike, and the
		// mixed closure go-zpkg/packages#225 exists to prevent would verify.
		// Slug() is byte-identical while the libc is unnamed, so nothing
		// already published changes identity.
		Platform: tgt.Slug(),
		Recipe:   dig,
	}
	for _, d := range deps {
		c.Deps = append(c.Deps, artifact.Dep{
			Project: d.Project,
			Version: d.Version,
			Hash:    hashOfPrefix(d.Path),
		})
	}
	// ⚠ APPENDED AFTER the declared ones and before the sort, so it takes its
	// place among them by name rather than by arrival. A recipe that declares
	// gnu.org/glibc itself would then contribute two entries — correct, and
	// visibly so: one is the recipe's own edge with a resolved prefix, the
	// other is the toolchain's with none.
	d, ok, err := libc.libcDep(tgt)
	if err != nil {
		return artifact.Concrete{}, err
	}
	if ok {
		c.Deps = append(c.Deps, d)
	}
	// Sorted, because this comes from walking a map and a hash that depended
	// on the order a map was walked would differ between two runs of the same
	// build — the one thing an identity must never do. Canonical() sorts its
	// own fields; this keeps the slice itself stable for everything else that
	// reads a Concrete, including the annotation a reader diffs by eye.
	sort.Slice(c.Deps, func(i, j int) bool {
		if c.Deps[i].Project != c.Deps[j].Project {
			return c.Deps[i].Project < c.Deps[j].Project
		}
		return c.Deps[i].Version < c.Deps[j].Version
	})
	return c, nil
}

// recipeDigest is the digest of the build PLAN, which is what Concrete.Recipe
// is contractually owed — never of the recipe file's bytes.
//
// ⛔ OVER THE PARSED VALUE RE-SERIALISED, so reformatting a recipe, reordering
// its mapping keys or rewriting its comments does not move it, and changing
// what it says does. Hashing the file instead would make a reflowed comment
// rebuild the world: every dependent's hash moves, every artifact is
// republished, and no binary differs. Spack strips comments and docstrings
// from package.py before hashing for the same reason, and Nix hashes the
// instantiated derivation rather than the expression.
func recipeDigest(recipe *pantry.Recipe) (string, error) {
	b, err := json.Marshal(recipe)
	if err != nil {
		// Not swallowed. A recipe that cannot be serialised has no digest, and
		// a build hashed over less than the recipe says is the defect the
		// digest exists to prevent.
		return "", fmt.Errorf("canonical recipe: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// hashOfPrefix reads a dependency's own identity out of the prefix it resolved
// to. "" when that prefix names a version and not a build — an older install,
// or one made before the layout carried the hash.
func hashOfPrefix(path string) string {
	if path == "" {
		return ""
	}
	v, ok := artifact.ParseStoreDirName(filepath.Base(path))
	if !ok {
		return ""
	}
	return v.Variant
}
