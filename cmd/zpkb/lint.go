package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/buildscript"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/recipefile"
)

// runLint implements `bk lint`: read every recipe in a pantry checkout and
// say which ones cannot be read.
//
// A pantry recipe is not a build input anyone can retry. A consumer fetches it
// over HTTP while resolving a closure, so a file that does not parse breaks
// every install of that project — silently, for everyone, with no build to go
// red first. That is the failure a pantry repository is uniquely able to
// cause, and the only one this checks for.
//
// It reads them with recipefile.Load, which is the loader the BUILDER uses:
// the same formats, the same schema, the same refusals. The check this
// replaces was a script that re-stated parts of the schema in another
// language, and it could only ever be a second opinion about what a recipe
// means — it went looking for package.yml and reported "the layout changed"
// the day the recipes became HCL, which is the mildest way that kind of
// divergence can present.
func runLint(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("lint", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the pantry checkout to read")
	// ⛔⛔ OUR OWN RECIPES DO NOT ALL LIVE UNDER projects/. go-zpkg/packages
	// keeps the platform-specific ones it authored at `wasip1/recipes/<project>`
	// and `windows/recipes/<project>` — 14 recipes this command could not be
	// pointed at, so every question asked of them got the answer a tree with no
	// recipes gets. A sweep that cannot read a corpus reports the same zero as
	// a clean one, and the empty-tree refusal below is the only reason this was
	// a visible failure rather than a silent pass.
	sub := fset.String("subdir", "projects", "the directory under -dir that holds the project tree")
	// ⛔⛔ PER TREE, AND THAT IS THE WHOLE DESIGN. Our recipes are written
	// from each project's own build system, so each must say which files
	// (go-zpkg/packages#431); an upstream recipe has no reason to carry that
	// and never will. Making it a schema requirement would refuse every
	// foreign recipe we still read — which is exactly the mistake that closing
	// `additionalProperties` made earlier today, when the bootstrap
	// toolchain's own recipes became unreadable (#427). A requirement about
	// OUR files belongs to the command that is pointed at our files.
	requireProv := fset.Bool("require-provenance", false,
		"fail a recipe that does not record which of the project's own files its build came from")
	// ⛔⛔ AN OVERLAY ENTRY IS A FRAGMENT, AND A PANTRY CANNOT BE MADE OF
	// FRAGMENTS. go-zpkg/recipes#50 reduced all 183 entries to the keys
	// they CHANGE, which was right for an overlay: artifact merges it over
	// PantryBase, so an omitted key is inherited from upstream and a small
	// curated tree can correct a stale constraint without forking 1700 files.
	//
	// It is exactly wrong for a pantry. `PantryBase` is still
	// pkgxdev/pantry compiled in (artifact/pkgx.go:68) and the overlay is merged
	// OVER it, so a fragment resolves only because somebody else's recipe is
	// underneath — the recipe we may not copy (go-zpkg/packages#431). Measured
	// here the day this flag was written: of 213 overlay recipes, 15 state a
	// `distributable`. The other 198 cannot build anything alone.
	//
	// So "we own 213 recipes" and "213 recipes of ours would resolve against an
	// empty upstream" are different claims, and only the second is what a
	// sovereign pantry needs. This flag is the difference, and it is per tree
	// for the same reason --require-provenance is: an overlay is ALLOWED to be
	// fragments, right up until it is asked to be the base.
	requireStandalone := fset.Bool("require-standalone", false,
		"fail a recipe that cannot resolve alone — one that needs another recipe merged underneath it")
	// ⛔⛔ HCL IS THE ONLY FORM OUR OWN RECIPES TAKE — a decision, taken by the
	// project's owner on 2026-11-15: "nous n'avons plus besoin YAML, on fait
	// tout en hcl". go-zpkg/recipes reached it the same morning: 222
	// package.hcl and zero package.yml.
	//
	// A STATED RULE WITH NOTHING ENFORCING IT IS A RULE THAT GETS BROKEN, and
	// this one is unusually easy to break by accident: `package.yml` is still a
	// name the loader reads, by design, so a yaml recipe added to our tree
	// works perfectly and nothing says it should not be there. The next person
	// converting an upstream recipe has every reason to paste the yaml first
	// and mean to convert it later.
	//
	// ⛔ PER TREE, like its two neighbours, and for the same reason: upstream's
	// pantry IS yaml and must stay readable — `PantryBase` is still
	// pkgxdev/pantry and 195 of our 222 recipes resolve only because it is
	// merged underneath. A schema rule would refuse the corpus we still depend
	// on. A requirement about OUR files belongs to the invocation pointed at
	// our files.
	//
	// ⭐ NO RATCHET, DELIBERATELY. --max-fragments and --max-no-provenance
	// exist because their checks could not be switched on at zero; this one is
	// at zero ALREADY, so a stated ceiling would be slack where none is needed.
	// Zero is the stricter answer and it is available.
	requireHCL := fset.Bool("require-hcl", false,
		"fail a recipe that is not written in HCL — our own trees hold package.hcl only")
	// ⛔⛔ A SCRIPT THE BUILDER'S OWN RENDERER REFUSES, FOUND BY READING ONE
	// RECIPE AND THEN SWEPT. openucx.org carried two `test` entries that were
	// one-key MAPS rather than strings:
	//
	//	{ "ucx_info -d | grep -q \"Transport" = "posix\"" }
	//
	// which is what the yaml line `- ucx_info -d | grep -q "Transport: posix"`
	// decodes to: the `: ` inside the quotes makes the whole list item a
	// mapping, the key ending at `"Transport` and the value beginning `posix"`.
	// The HCL conversion carried that structure faithfully, so the defect
	// predated it by however long the yaml had been there.
	//
	// ⛔ AND IT WAS NOT A SILENT SKIP. buildscript.scriptItem sees a map, finds
	// no `if` and no `run`, and renderRun(nil) falls to its default arm:
	// "script step needs a `run` string or list". So the ENTIRE test block was
	// unrenderable and `zpkb test openucx.org` could not run at all — while
	// `lint` was green, because parsing a recipe and rendering its scripts are
	// different questions.
	//
	// THE JUDGE IS buildscript.Generate ITSELF, deliberately. A rule here about
	// what a script entry may contain would re-state the schema in a second
	// place, and the day the two disagreed the lane and the build would
	// disagree too — which is the defect this file's first check already
	// carries in its own comment.
	//
	// ⭐ No ratchet: swept over all 222 recipes of go-zpkg/recipes, that
	// one block was the only refusal in the tree, so zero is where this starts.
	renderScripts := fset.Bool("render-scripts", false,
		"fail a recipe whose build or test script the builder's own renderer cannot render")
	// ⛔⛔ FOUR RECIPES SHIPPED READING A VARIABLE THIS BUILDER DOES NOT EXPORT,
	// across THREE sweeps that each believed they were the last
	// (go-zpkg/zpkb#494):
	//
	//	kernel.org/linux:75   $ZBK_CC_FREESTANDING   is ZPKB_CC_FREESTANDING
	//	unbound.net:17        $PKGX_DIR              is ZPKG_DIR
	//	llvm.org:184          $PKGX_DIR              is ZPKG_DIR
	//	rust-lang.org/cargo   BREWKIT_TARGET         is ZPKB_TARGET
	//
	// A shell expands an unset variable to the empty string and exits 0, so
	// every one of these is SILENT: no build fails and no test looks. The worst
	// was not a dropped flag — unbound's `sed -i -e "s|$PKGX_DIR/|…|g"` ran as
	// `s|/|…|g`, replacing every slash in an installed script, and the next line
	// deleted the .bak that would have shown it. The kernel's passed `CC=""` on
	// a make command line, which beats kbuild's own assignment.
	//
	// go-zpkg/recipes#97, which moved these recipes to the MIDDLE spelling
	// of the prefix, predicted this in its own description: "a recipe switched
	// ahead of it reads an UNSET variable, and for these two that is silent". It
	// was right, and it happened again to one of the two recipes it described,
	// because the prefix it moved them to was itself renamed afterwards. Prose
	// cannot close this; a check can.
	//
	// THE AUTHORITY IS THE EXPORTER ITSELF: buildscript.ExportedNames() renders
	// `Wrap`/`WrapTest` across every mode and reads the names back out, and
	// build.PassThroughEnv names what SanitizedEnv forwards. A list written here
	// would be a fifth copy of the information that already drifted four times.
	//
	// ⛔ PER TREE, like its three neighbours above, and for the sharper reason:
	// upstream's pantry is pkgx's, where `$PKGX_DIR` is CORRECT — pkgx exports
	// it. An unconditional check would refuse the foreign corpus 186 of our own
	// recipes still resolve against, for reading a variable that is right in its
	// own builder. A requirement about what OUR builder provides belongs to the
	// invocation pointed at OUR recipes.
	//
	// ⭐ NO RATCHET: measured over go-zpkg/recipes at 233 recipes after
	// go-zpkg/recipes#138 fixed the kernel's, this reports ZERO, so a
	// stated ceiling would be slack where none is needed.
	requireKnownEnv := fset.Bool("require-known-env", false,
		"fail a recipe whose script reads a build-environment variable in our own "+
			"namespaces that the builder does not export")
	// ⛔⛔ A GATE THAT STARTS RED IS NOT A GATE, IT IS A LIGHT NOBODY READS, and
	// the recipes tree's own ci.yml carries that lesson already: its lint step
	// invoked a module path that no longer existed, so every pull request after
	// the rename failed there, on the toolchain rather than on a recipe, and no
	// recipe was read by the builder's loader for weeks.
	//
	// --require-standalone on our overlay reports 197 of 213 today. Turning it
	// on as a hard zero would be that same red light; leaving it off until the
	// last recipe is written means nothing protects the 16 that already stand
	// alone. A RATCHET is the third option: state the number, refuse an
	// increase, and refuse a stale ceiling too.
	//
	// Refusing to be UNDER the ceiling is the part that makes it a ratchet
	// rather than a budget. A ceiling nobody lowers stops describing the tree
	// within a week, and then a regression hides inside the slack — which is
	// the same failure as a coverage gate left at a number the code has passed.
	// -1 means "not given": zero is a real and much stricter answer.
	maxFragments := fset.Int("max-fragments", -1,
		"with --require-standalone: the number of fragments this tree still has. "+
			"More fails as a regression, FEWER fails as a ceiling to lower")
	// ⛔⛔ --require-provenance NEEDED THE SAME THIRD OPTION, AND ITS OWN LANE
	// SAID SO. go-zpkg/recipes' ci.yml carried, in a comment beside the
	// step it did NOT add: "--require-provenance is NOT here yet. 14 of 216
	// record none, and there is no ratchet for it, so turning it on would be the
	// red light this avoids. It belongs here once those 14 are written or once it
	// has a ceiling of its own."
	//
	// That is the gap this flag closes, and the choice between the two halves of
	// that sentence is not a toss-up. Writing the 14 means reading fourteen
	// projects' build systems — kernel.org/linux and llama.cpp among them — so
	// "once those 14 are written" is a campaign, and until it ends NOTHING
	// protects the 208 recipes that already record provenance. A new recipe
	// landing without one is invisible today.
	//
	// Measured 2026-11-15 on the overlay at 097fc86, with the judge the lane
	// runs (`zpkb@main`, v0.76.1-0.20261114072102-d2e01c8b0687) and with the
	// v0.76.0 binary installed here — both answer 14 of 222, so the number below
	// is not an artefact of which build asked.
	maxNoProv := fset.Int("max-no-provenance", -1,
		"with --require-provenance: the number of recipes in this tree that still record none. "+
			"More fails as a regression, FEWER fails as a ceiling to lower")
	// ⛔⛔ AN OVERRIDE THE LOADERS NO LONGER APPLY, AND NOTHING SAID SO
	// (go-zpkg/zpkb#516). Since v0.90.0 a STANDALONE overlay recipe is the whole
	// recipe: LoadBuildRecipe and LoadMerged skip set.ApplyTo for it. So every
	// logical override (go-zpkg/packages' overrides/*.hcl) whose project has a
	// standalone recipe in THIS tree is dead — parsed, reviewed, applied by
	// nothing — and that is harmless only if its fix is already in the recipe.
	//
	// The judge is the one the loaders use (artifact.IsStandalone, through
	// missingEssentials), not a second definition. A WARNING by default, because
	// the overlap must be carried into the recipes before it can be a refusal;
	// --require-live-overrides is the refusal.
	overridesDir := fset.String("overrides", "",
		"a directory of logical overrides (go-zpkg/packages' overrides/): report each one whose "+
			"project has a standalone recipe in this tree, because the loaders no longer apply it")
	requireLive := fset.Bool("require-live-overrides", false,
		"with --overrides: fail when an override is dead instead of warning")
	// ⛔⛔ NETWORK-USING, SO A FLAG. See newestPinGaps: a recipe that pins
	// sha256 digests while `versions:` resolves a newer, unpinned version is a
	// default build that is a refusal (3 times on 2026-11-20).
	checkNewestPinned := fset.Bool("check-newest-pinned", false,
		"resolve each pinning recipe's versions as the builder does (network) and fail one "+
			"whose NEWEST version has no sha256 pin")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if *requireLive && *overridesDir == "" {
		fmt.Fprintln(stderr, "lint: --require-live-overrides judges the overrides "+
			"--overrides names, and does nothing without it")
		return 2
	}
	var overrideSet *logical.Set
	if *overridesDir != "" {
		var err error
		if overrideSet, err = logical.LoadDir(*overridesDir); err != nil {
			fmt.Fprintf(stderr, "lint: %v\n", err)
			return 1
		}
		// An empty directory is the wrong directory, not a clean tree.
		if len(overrideSet.Projects()) == 0 {
			fmt.Fprintf(stderr, "lint: no override under %s — is that the right directory?\n", *overridesDir)
			return 1
		}
	}

	// ⛔ A FLAG THAT SILENTLY DOES NOTHING IS WORSE THAN A MISSING ONE: a lane
	// that spells --max-fragments without --require-standalone would record a
	// number nobody checks, and read as protected.
	if *maxFragments >= 0 && !*requireStandalone {
		fmt.Fprintln(stderr, "lint: --max-fragments is a ceiling on what "+
			"--require-standalone counts, and does nothing without it")
		return 2
	}
	if *maxNoProv >= 0 && !*requireProv {
		fmt.Fprintln(stderr, "lint: --max-no-provenance is a ceiling on what "+
			"--require-provenance counts, and does nothing without it")
		return 2
	}

	root := filepath.Join(*dir, *sub)
	// One walk, and the file NAMES come back with it: --require-hcl judges the
	// names, every other check judges the content, and both must be talking
	// about the same tree.
	recipeFiles, err := lintRecipeFiles(root)
	if err != nil {
		fmt.Fprintf(stderr, "lint: %v\n", err)
		return 1
	}
	projects := make([]string, 0, len(recipeFiles))
	for proj := range recipeFiles {
		projects = append(projects, proj)
	}
	sort.Strings(projects)
	// An empty tree is a FAILURE, not a pass. A sweep that could not find its
	// corpus reports the same "no problems" as one that read it all, and the
	// one thing that distinguishes them is saying how many were read.
	if len(projects) == 0 {
		fmt.Fprintf(stderr, "lint: no recipe under %s — the layout changed\n", root)
		return 1
	}

	// Built once, before the walk: rendering the wrapper in every mode for each
	// of 233 recipes would be the same answer 233 times.
	var knownEnv map[string]bool
	if *requireKnownEnv {
		knownEnv = map[string]bool{}
		for _, n := range buildscript.ExportedNames() {
			knownEnv[n] = true
		}
		// The names SanitizedEnv always sets, taken from its OUTPUT rather than
		// restated: `PATH=…`, `ZPKG_DIR=…` and the rest.
		for _, kv := range build.SanitizedEnv("", "") {
			if i := strings.IndexByte(kv, '='); i > 0 {
				knownEnv[kv[:i]] = true
			}
		}
		// And the ones it forwards only when the caller has them, which is why
		// the list exists separately from the result.
		for _, n := range build.PassThroughEnv {
			knownEnv[n] = true
		}
	}

	var bad, unrecorded, fragments, signedSha, unrendered, unknownEnv, dead, unpinnedNewest []string
	for _, proj := range projects {
		// The project's DIRECTORY rather than (dir, project): the loader that
		// takes a pantry and a project joins `projects/` in, which is right for
		// a pantry and wrong for the two trees of ours that are not laid out
		// that way. The DOCUMENT comes back from the same read as the recipe,
		// because --require-standalone asks which keys the file STATES and the
		// typed recipe cannot answer that.
		pdir := filepath.Join(root, filepath.FromSlash(proj))
		r, doc, err := recipefile.LoadWithDoc(pdir)
		if err != nil {
			bad = append(bad, fmt.Sprintf("  %s: %v", proj, err))
			continue
		}
		// A recipe with no distributable packages nothing of its own — a set,
		// or a project whose files come from its dependencies — so there is no
		// build to have derived from anything.
		if *requireProv && r.Provenance == nil && r.Distributable != nil {
			unrecorded = append(unrecorded, "  "+proj)
		}
		if miss := missingEssentials(doc); *requireStandalone && len(miss) > 0 {
			fragments = append(fragments, fmt.Sprintf("  %s: states no %s",
				proj, strings.Join(miss, ", no ")))
		}
		if overrideSet != nil && overrideSet.For(proj) != nil && len(missingEssentials(doc)) == 0 {
			dead = append(dead, fmt.Sprintf("  %s: %s — %s", proj, overrideSet.Files[proj],
				deadOverrideVerdict(overrideSet.For(proj), doc)))
		}
		if *checkNewestPinned {
			for _, g := range newestPinGaps(r.Versions, r.Distributable, r.Sources) {
				unpinnedNewest = append(unpinnedNewest, fmt.Sprintf("  %s: %s", proj, g))
			}
		}
		if u := shaNamesASignature(r.Distributable); u != "" {
			signedSha = append(signedSha, fmt.Sprintf("  %s: sha = %q", proj, u))
		}
		// Rendered with ZERO Options on purpose: no tokens, no target. A
		// moustache then stays literal and an `if:` guard simply selects
		// nothing, so what is left is the only question asked here — whether
		// the renderer can read the script's SHAPE at all. Swept over 222 real
		// recipes with exactly these options, one block was refused and it was
		// a genuine defect, so this produces no false positives on the corpus
		// it is for.
		if *renderScripts {
			for _, block := range []string{"build", "test"} {
				b, ok := doc[block].(map[string]any)
				if !ok || b["script"] == nil {
					continue
				}
				if _, err := buildscript.Generate(b["script"], buildscript.Options{}); err != nil {
					unrendered = append(unrendered,
						fmt.Sprintf("  %s: %s: %v", proj, block, err))
				}
			}
		}
		if *requireKnownEnv {
			for _, block := range []string{"build", "test"} {
				b, ok := doc[block].(map[string]any)
				if !ok || b["script"] == nil {
					continue
				}
				// The whole BLOCK rather than its `script`, which the check
				// above passes: Generate's map branch prepends the recipe's own
				// `env` as `export K=…` lines, so the rendered text carries both
				// the references to check and the recipe's own assignments that
				// exempt them. Handing it `b["script"]` alone would refuse a
				// recipe for reading a variable it sets itself two lines up.
				script, err := buildscript.Generate(b, buildscript.Options{})
				if err != nil {
					// Unrenderable is --render-scripts' finding, not this one.
					// Reporting it twice would make one defect look like two.
					continue
				}
				for _, name := range unknownEnvRefs(script, knownEnv) {
					unknownEnv = append(unknownEnv,
						fmt.Sprintf("  %s: %s: $%s", proj, block, name))
				}
			}
		}
	}
	fmt.Fprintf(stdout, "%d recipe(s) read from %s\n", len(projects), root)
	// Judged on the NAMES, from the same walk that produced the count above. A
	// directory holding both forms is named too: the loader would prefer the
	// HCL and the yaml would sit there unread, which is the state this refuses.
	var notHCL []string
	if *requireHCL {
		for _, proj := range projects {
			for _, name := range recipeFiles[proj] {
				if name != hclRecipeName {
					notHCL = append(notHCL, fmt.Sprintf("  %s: %s", proj, name))
				}
			}
		}
	}
	if len(unrendered) > 0 {
		sort.Strings(unrendered)
		fmt.Fprintf(stderr, "%d script block(s) of %d project(s) cannot be rendered by the "+
			"builder's own renderer, so the step they describe would never run — `lint` parsing a "+
			"recipe and `buildscript` rendering its script are different questions, and only this "+
			"one is asked here (go-zpkg/recipes#107):\n", len(unrendered), len(projects))
		fmt.Fprintln(stderr, strings.Join(unrendered, "\n"))
	}
	if len(unknownEnv) > 0 {
		sort.Strings(unknownEnv)
		fmt.Fprintf(stderr, "%d reference(s) in %d project(s) read a build-environment variable "+
			"in our own namespaces that this builder does not export, so the shell expands it to "+
			"the EMPTY STRING and exits 0 — no build fails and no test looks. Four recipes shipped "+
			"one across three sweeps, the last passing `CC=\"\"` to a kernel build "+
			"(go-zpkg/zpkb#494). The names the builder does provide come from "+
			"buildscript.ExportedNames() and build.PassThroughEnv:\n", len(unknownEnv), len(projects))
		fmt.Fprintln(stderr, strings.Join(unknownEnv, "\n"))
	}
	if len(unpinnedNewest) > 0 {
		sort.Strings(unpinnedNewest)
		fmt.Fprintf(stderr, "%d pin(s) of recipes whose NEWEST resolved version has no sha256 pin: "+
			"a consumer asking \"*\" gets that version and the builder refuses it, because a recipe "+
			"that pins is fail-closed. Pin the newest, or stop `versions:` resolving it:\n",
			len(unpinnedNewest))
		fmt.Fprintln(stderr, strings.Join(unpinnedNewest, "\n"))
	}
	if overrideSet != nil {
		fmt.Fprintf(stdout, "%d override(s) read from %s\n", len(overrideSet.Projects()), *overridesDir)
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		fmt.Fprintf(stderr, "%d override(s) are DEAD: the project has a standalone recipe in %s, "+
			"which is the whole recipe and is built without its logical overrides "+
			"(go-zpkg/zpkb#514, #516). Carry the fix into the recipe, citing the override, "+
			"and delete the override — or say in the recipe why it does not apply:\n", len(dead), root)
		fmt.Fprintln(stderr, strings.Join(dead, "\n"))
	}
	if len(notHCL) > 0 {
		sort.Strings(notHCL)
		fmt.Fprintf(stderr, "%d recipe file(s) of %d project(s) are not %s — our own trees hold "+
			"HCL only, and `zpkb tohcl` DROPS EVERY COMMENT, so a conversion is read and "+
			"rewritten by a person rather than piped (go-zpkg/recipes):\n",
			len(notHCL), len(projects), hclRecipeName)
		fmt.Fprintln(stderr, strings.Join(notHCL, "\n"))
	}
	// ⛔⛔ UNCONDITIONAL, AND THE ONLY CHECK HERE THAT IS. The others ask about
	// a tree's completeness, which is a campaign; this one asks whether a
	// recipe states something that CANNOT be true, and a flag for it would be
	// a flag somebody forgets at exactly the wrong moment.
	if len(signedSha) > 0 {
		sort.Strings(signedSha)
		fmt.Fprintf(stderr, "%d recipe(s) point `sha` at a detached SIGNATURE, and `sha` is "+
			"where the expected SHA-256 is PUBLISHED — the build fetches it and compares "+
			"(build/runner.go), so a .sig there fails every build and `zpkb lint` is the only "+
			"thing that can see it, because linting does not fetch. The signature belongs in "+
			"`provenance` until go-zpkg/zpkb#282 gives it a field:\n", len(signedSha))
		fmt.Fprintln(stderr, strings.Join(signedSha, "\n"))
		return 1
	}
	if len(unrecorded) > 0 {
		sort.Strings(unrecorded)
		fmt.Fprintf(stderr, "%d of %d recipe(s) record no provenance — each must say which of "+
			"the project's OWN files its build was written from, because that is the basis on "+
			"which it may exist at all (go-zpkg/packages#431):\n",
			len(unrecorded), len(projects))
		fmt.Fprintln(stderr, strings.Join(unrecorded, "\n"))
		// Tolerated is never hidden: the recipes are still named above, and this
		// says where the obligation now sits.
		if *maxNoProv == len(unrecorded) {
			fmt.Fprintf(stderr, "lint: at the stated ceiling of %d without provenance; "+
				"each one written must lower it\n", *maxNoProv)
		}
	}
	// Under the ceiling: the tree improved and the ceiling did not. Nothing is
	// wrong with the recipes — the number in the lane is what needs the edit,
	// and the message says which number to write.
	if *maxNoProv > len(unrecorded) {
		fmt.Fprintf(stderr, "lint: %d recipe(s) record no provenance, and "+
			"--max-no-provenance says %d: lower it to %d. A ceiling nobody lowers stops "+
			"describing the tree, and then a regression hides in the slack\n",
			len(unrecorded), *maxNoProv, len(unrecorded))
		return 1
	}
	// Under the ceiling: the tree improved and the ceiling did not. Reported on
	// stdout as a success, because nothing is wrong with the recipes — the
	// number in the lane is what needs the edit, and the message says which.
	if *maxFragments > len(fragments) {
		fmt.Fprintf(stderr, "lint: %d fragment(s), and --max-fragments says %d: "+
			"lower it to %d. A ceiling nobody lowers stops describing the tree, "+
			"and then a regression hides in the slack\n",
			len(fragments), *maxFragments, len(fragments))
		return 1
	}
	if len(fragments) > 0 {
		sort.Strings(fragments)
		fmt.Fprintf(stderr, "%d of %d recipe(s) cannot resolve alone — each needs another "+
			"recipe merged underneath it to say where its source comes from or how to build "+
			"it, and the only tree underneath ours is the upstream we may not copy "+
			"(go-zpkg/packages#431):\n",
			len(fragments), len(projects))
		fmt.Fprintln(stderr, strings.Join(fragments, "\n"))
		if *maxFragments == len(fragments) {
			fmt.Fprintf(stderr, "lint: at the stated ceiling of %d; each recipe completed "+
				"must lower it\n", *maxFragments)
		}
	}
	if len(bad) > 0 {
		fmt.Fprintln(stderr, strings.Join(bad, "\n"))
		fmt.Fprintf(stderr, "%d recipe(s) cannot be read\n", len(bad))
		return 1
	}
	// Reported after the unreadable ones, and a failure in its own right: a
	// run that printed the list and exited 0 is a list nobody acts on. At a
	// STATED ceiling they are tolerated, which is what stating a number means;
	// without --max-no-provenance the tolerance is zero, the stricter reading,
	// and that stays the default.
	if len(unrecorded) > 0 && *maxNoProv != len(unrecorded) {
		return 1
	}
	// At or under a STATED ceiling the fragments are tolerated — that is what
	// stating a number means. Without --max-fragments the tolerance is zero,
	// which is the stricter reading and stays the default.
	if len(fragments) > 0 && *maxFragments != len(fragments) {
		return 1
	}
	// No tolerance and no ceiling, for the reason given where the flag is
	// declared: this check is at zero already.
	if len(notHCL) > 0 {
		return 1
	}
	if *requireLive && len(dead) > 0 {
		return 1
	}
	// Also no tolerance and no ceiling: the tree it was written for has none.
	if len(unrendered) > 0 {
		return 1
	}
	// No ceiling either, for the reason given where the flag is declared: the
	// tree this was written for reports zero once go-zpkg/recipes#138
	// is in.
	if len(unknownEnv) > 0 {
		return 1
	}
	if len(unpinnedNewest) > 0 {
		return 1
	}
	return 0
}

// deadOverrideVerdict says whether a dead override's fix is already in the
// recipe that retired it, by running its operations against a COPY of the
// recipe with the applier the builder uses: an operation that would still
// change the document is a fix the recipe LACKS (a defect to carry over), one
// that finds it already true is a fix the recipe has. Each operation is judged
// alone, in order, so one gone premise does not hide the rest.
func deadOverrideVerdict(o *logical.Override, doc map[string]any) string {
	cp, _ := cloneDoc(doc).(map[string]any)
	var missing, gone []string
	for _, op := range o.Ops {
		res, err := logical.Apply(cp, []logical.Op{op})
		switch {
		case err != nil:
			gone = append(gone, op.Path.String())
		case len(res) == 1 && res[0].Outcome == logical.Applied:
			missing = append(missing, op.Path.String())
		}
	}
	switch {
	case len(missing) > 0:
		return "fix MISSING from the recipe: " + strings.Join(missing, ", ")
	case len(gone) > 0:
		return "premise gone in the recipe: " + strings.Join(gone, ", ")
	}
	return "fix already in the recipe"
}

// cloneDoc deep-copies a recipe document, because Apply edits in place and the
// document is still the recipe's other checks' input.
func cloneDoc(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = cloneDoc(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = cloneDoc(e)
		}
		return l
	}
	return v
}

// hclRecipeName is the one recipe file name our own trees carry. It is a
// LITERAL rather than recipefile.Names[0] on purpose: indexing a list would
// make this gate's meaning depend on that list's ORDER, so reordering it — a
// change with no other consequence — would silently start accepting yaml.
// TestTheHCLNameIsARecipeName keeps the literal honest against the loader.
const hclRecipeName = "package.hcl"

// essentials are the keys a recipe must STATE to stand on its own: where its
// versions come from, where its content comes from, and how to turn that into a
// package. Miss any one and the recipe is an amendment to another recipe.
//
// `build` is in the list on purpose, though a fragment that lacked only `build`
// would be unusual: these are the three keys the factory reads to produce a
// artifact, and a list that held two of them would answer a narrower question
// than the one asked.
// signatureExts are the names a DETACHED SIGNATURE goes by. `.sig` and `.asc`
// are OpenPGP's two spellings (binary and armoured) and `.sign` is kernel.org's.
var signatureExts = []string{".sig", ".asc", ".sign"}

// shaNamesASignature returns a recipe's `distributable.sha` when it points at a
// detached signature instead of a published checksum.
//
// ⛔⛔ THREE RECIPES SHIPPED THIS AND NONE OF THEM COULD HAVE BUILT.
// `schema/package.schema.json:141` defines `sha` as "where the expected SHA-256
// of the archive is published, usually ${{url}}.sha256 — the build fetches it
// and refuses a mismatch", and `build/runner.go:769-781` does exactly that.
// Measured with this repository's own reader on gnu.org/grep's:
//
//	fetch.DeclaredSHA256(".../grep-3.12.tar.xz.sig", "grep-3.12.tar.xz")
//	→ no line names grep-3.12.tar.xz — the server returned text, not an
//	  archive: "-----BEGIN PGP SIGNATURE----- …"
//
// and a checksum file that cannot be READ is a build failure on purpose
// (runner.go:746-749). gnu.org/gzip, gnu.org/grep and gnu.org/bash each carried
// one, bash being a base-toolchain member, and the lane stayed green because
// linting does not fetch (go-zpkg/recipes#89).
//
// The author's error was not careless: `zpkb sourcepin` PRINTED a `sig = …` line
// under the `sha256` block it offers for pasting, and `sig` is read by nothing
// (#282), so the nearest key that existed was `sha`. That output is now a
// comment; this is the half that catches a recipe whatever suggested it.
//
// It matches on the extension and not on fetching anything: a URL ending `.sig`
// is never a checksum file, whatever it contains, and a check that had to
// download would be a check the lane cannot run offline.
func shaNamesASignature(distributable any) string {
	m, ok := distributable.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m["sha"].(string)
	lower := strings.ToLower(s)
	for _, ext := range signatureExts {
		if strings.HasSuffix(lower, ext) {
			return s
		}
	}
	return ""
}

// envRefRE matches a shell variable REFERENCE: `$NAME` and `${NAME…}`, the
// second form including the modifiers a reference may carry (`${NAME:-default}`,
// `${NAME:+…}`), so the name is captured and the modifier ignored.
//
// `$$NAME` is not excluded here and does not need to be: by the time a script
// reaches this check, HCL has already turned `$${` into `${`, so what is read
// is what the shell will read. That escape is a recipe-authoring concern
// (go-zpkg/recipes#131), not a shell one.
var envRefRE = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)

// envAssignRE matches a name the script ASSIGNS itself, in either spelling a
// rendered recipe uses: `export NAME=` from an `env` block, and a bare
// `NAME=value` written in a script step (kernel.org/linux sets KERNEL_IMAGE
// that way, then reads it two steps later).
var envAssignRE = regexp.MustCompile(`(?m)(?:^[[:space:]]*|export[[:space:]]+)([A-Za-z_][A-Za-z0-9_]*)=`)

// unknownEnvRefs names the variables a rendered script reads that are in one of
// OUR namespaces, that the builder does not export, and that the script does
// not set itself — sorted, each reported once however often it is read.
//
// ⚠ THE NAMESPACE FILTER IS WHAT KEEPS THIS FROM BEING A SHELL LINTER. A
// recipe's script is a project's own build system; `$ACLOCAL_PATH`,
// `$HOMEBREW_PREFIX` or a variable the project's configure exports are none of
// our business, and refusing them would be an opinion about other people's
// builds. A misspelt name under `ZPKB_`/`ZPKG_` — or ANY name under the dead
// `ZBK_`/`BK_`/`BREWKIT_`/`PKGX_` — is always ours and always a defect.
func unknownEnvRefs(script string, known map[string]bool) []string {
	local := map[string]bool{}
	for _, m := range envAssignRE.FindAllStringSubmatch(script, -1) {
		local[m[1]] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range envRefRE.FindAllStringSubmatch(script, -1) {
		name := m[1]
		if known[name] || local[name] || seen[name] {
			continue
		}
		ours := false
		for _, p := range buildscript.OurEnvPrefixes {
			if strings.HasPrefix(name, p) {
				ours = true
				break
			}
		}
		if !ours {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// missingEssentials names the essential keys a recipe document does not state.
//
// ⛔ THE DEFINITION IS artifact.MissingEssentials, NOT A COPY OF IT
// (go-zpkg/zpkb#514). "Standalone" decides what the factory builds and what a
// consumer resolves, so lint, closure, the loaders here and artifact's
// resolver must all call the one function; a second spelling is how they
// would disagree about what a fragment is.
func missingEssentials(doc map[string]any) []string {
	return artifact.MissingEssentials(doc)
}

// lintProjects lists the project directories under root, by the recipe file
// each one holds. A directory is a project because it has a recipe, not
// because of where it sits: the pantry nests them (x.org/protocol/xcb), so
// depth says nothing.
func lintProjects(root string) ([]string, error) {
	byProject, err := lintRecipeFiles(root)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(byProject))
	for proj := range byProject {
		out = append(out, proj)
	}
	sort.Strings(out)
	return out, nil
}

// lintRecipeFiles is the ONE walk, and it reports which recipe FILE NAMES each
// project holds rather than only that it is a project. --require-hcl needs the
// names; a second walk beside this one would be two readings of one tree, and
// the day they disagreed the count and the verdict would come from different
// corpora.
//
// A project may hold MORE THAN ONE name: a directory with both package.hcl and
// package.yml is legal, and recipefile.Load prefers the HCL. That is precisely
// the case --require-hcl must still refuse, so every name is kept rather than
// the one the loader would pick.
func lintRecipeFiles(root string) (map[string][]string, error) {
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !recipefile.IsRecipe(d.Name()) {
			return nil
		}
		// Sliced rather than made relative: the path came from WalkDir(root),
		// so it is under root by construction and filepath.Rel could only fail
		// on inputs this cannot produce — an error arm no test could reach.
		// A recipe sitting directly in projects/ belongs to no project and is
		// left alone.
		dir := filepath.ToSlash(filepath.Dir(p))
		base := filepath.ToSlash(root)
		if dir == base {
			return nil
		}
		proj := strings.TrimPrefix(dir, base+"/")
		out[proj] = append(out[proj], d.Name())
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for proj := range out {
		sort.Strings(out[proj])
	}
	return out, nil
}
