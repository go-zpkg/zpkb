package main

import (
	"fmt"

	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/versions"
)

// lintResolve is the resolver `--check-newest-pinned` asks for the newest
// version: versions.Resolve, the function `zpkb test` and `zpkb lock` call with
// the constraint "*" a consumer sends. A variable so the tests answer without a
// network.
var lintResolve = versions.Resolve

// newestPinGaps answers, for ONE recipe, the question the builder asks at build
// time and no lint asked before: the newest version `versions:` resolves — the
// one a consumer gets for "*" — is it pinned?
//
// ⛔⛔ THREE TIMES ON 2026-11-20 in go-zpkg/recipes: a recipe pinned a
// `distributable.sha256` map, its `versions:` resolved a NEWER version that had
// no pin, and build.pinnedDigest REFUSES a version a pinning recipe does not
// name (fail-closed, on purpose). The default build was therefore a refusal and
// no lint could see it, because linting parses and does not resolve:
// gnu.org/gcc/libstdcxx (resolved 16.2.0, pinned 14.4.0), tcl-lang.org
// (9.0.5rc0 and 9.1.0 resolved) and llvm.org (23.1.6 resolved, 22.1.8 pinned).
//
// THE JUDGES ARE THE BUILDER'S: versions.Resolve for the version and
// build.PinnedDigest (the one function oneSource calls) for the pin, so this
// cannot disagree with a build about what "pinned" means. Both `distributable`
// (a map, or a list of maps) and every `sources:` entry are read, because both
// carry a version-keyed sha256 since #424 / v0.92.0.
//
// A recipe that pins nothing is skipped BEFORE resolving: it would be a
// network round trip to answer a question it cannot fail, and it must not be
// refused for being unable to reach its upstream.
//
// TWO KINDS OF "NO" (go-zpkg/zpkb#524). A newest version that is resolved and
// not pinned is the defect this check exists for: the first result. A newest
// version that could not be RESOLVED is not evidence about the pin: the second
// result, an error, which the caller reports in its own section. The caller
// tells a host that never answered (versions.IsTransient: timeouts, 5xx, 429
// after the whole retry budget) from a source that answered "no" (404, no
// candidate, a regexp that matches nothing), because only the second is a
// recipe defect.
func newestPinGaps(spec, dist, sources any) ([]string, error) {
	type pinned struct {
		label string
		sha   any
	}
	var pins []pinned
	addEntry := func(label string, e any) {
		if m, ok := e.(map[string]any); ok && m["sha256"] != nil {
			pins = append(pins, pinned{label, m["sha256"]})
		}
	}
	if lst, ok := dist.([]any); ok {
		for i, e := range lst {
			addEntry(fmt.Sprintf("distributable[%d]", i), e)
		}
	} else {
		addEntry("distributable", dist)
	}
	if lst, ok := sources.([]any); ok {
		for i, e := range lst {
			addEntry(fmt.Sprintf("sources[%d]", i), e)
		}
	}
	if len(pins) == 0 {
		return nil, nil
	}
	newest, _, err := lintResolve(spec, "*")
	if err != nil {
		// Not a pass: an unresolved recipe is one this check could not judge,
		// and a sweep that cannot read reports the same zero as a clean one.
		return nil, err
	}
	var out []string
	for _, p := range pins {
		if _, err := build.PinnedDigest(p.sha, newest); err != nil {
			out = append(out, fmt.Sprintf("%s: newest resolved version is %s: %v", p.label, newest, err))
		}
	}
	return out, nil
}
