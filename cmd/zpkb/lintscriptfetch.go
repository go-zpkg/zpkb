package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ⛔⛔ A BUILD SCRIPT THAT FETCHES A REMOTE ARTIFACT HAS NO DIGEST ON IT
// (go-zpkg/zpkb#487). `distributable` pins the main source and `sources` (since
// v0.92.0) pins every extra one, each with a mandatory sha256. A `curl` in a
// script fetches outside both, so the bytes that end up in the published package
// are whatever the host served at build time.
//
// WHAT COUNTS is the definition the issue measured on pkgxdev/pantry (113
// recipes, 156 lines) after its own correction, and it is reused unchanged so the
// two numbers can be compared:
//
//   - the commands `curl`, `wget`, `git clone`, `svn checkout`, `hg clone`, at a
//     word boundary (`curl-config` is not `curl`), anywhere on a script line, so
//     `$(…)`, backticks and pipes are covered;
//   - in `build.script` and `build.env`; the `test` block is counted APART,
//     because an unpinned artifact in the build ships and one in a test only
//     makes the test depend on a remote host. The ceiling bounds the build.
//
// WHAT DOES NOT COUNT, with the reason the issue gave:
//
//   - `pip install`, `npm install`, `go install`, `cargo install`. The first
//     version of the detector matched them and read 549 recipes, ~5x too high:
//     they build the source the builder ALREADY fetched and pinned and reach the
//     network only for language-level dependencies, which is resolution and not
//     source substitution. A different defect, not folded in here.
//   - a comment line (`# … confirmed with curl`): added here, the issue's sweep
//     did not exclude it. It removed one false positive from our own tree;
//     its effect on the pantry number is stated in the README;
//   - a line naming the loopback or `--version`/`--help`: a test probing a closed
//     port, or `curl --version`, fetches nothing.
var scriptFetcher = regexp.MustCompile(`(^|[\s;&|(])(curl|wget|git clone|svn checkout|hg clone)\b`)

var scriptFetchLocalOnly = regexp.MustCompile(`127\.0\.0\.1|localhost|--version|--help`)

// The shapes the issue found, because one undifferentiated count would send the
// reader to one remedy when there are several.
var (
	// floating: addressed by a branch, so the bytes are whatever it holds today.
	// The issue's worst case: `tessdata/blob/main/eng.traineddata?raw=true`.
	shapeFloating = regexp.MustCompile(`/(blob|raw|tree)/(main|master|HEAD)/|archive/refs/heads/`)
	shapePatch    = regexp.MustCompile(`\.(patch|diff)\b|\bpatch\s+-p`)
	shapeArchive  = regexp.MustCompile(`\.(tar\.[a-z0-9]+|tgz|tbz2|zip)\b`)
)

// fetchShape names the remedy a fetch line wants.
func fetchShape(line string) string {
	switch {
	case shapeFloating.MatchString(line):
		return "floating"
	case shapePatch.MatchString(line):
		return "patch"
	case shapeArchive.MatchString(line):
		return "archive"
	}
	return "other"
}

// stringsOfNode flattens every string a recipe node holds, so a script given as a
// scalar, a list, or a list of {run: …} maps is read the same way. Judge and
// subject must count alike: the builder renders all three shapes.
func stringsOfNode(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case []any:
		for _, e := range t {
			out = append(out, stringsOfNode(e)...)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, stringsOfNode(t[k])...)
		}
	}
	return out
}

// fetchLines returns the fetch lines of one node, trimmed.
func fetchLines(node any) []string {
	var out []string
	for _, s := range stringsOfNode(node) {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			// A shell comment fetches nothing: rust-lang.org/cargo's, in our own
			// tree, says "confirmed by a second fetch with curl" and nothing more.
			if strings.HasPrefix(line, "#") {
				continue
			}
			if scriptFetcher.MatchString(line) && !scriptFetchLocalOnly.MatchString(line) {
				out = append(out, line)
			}
		}
	}
	return out
}

// scriptFetches reports the fetch lines of a recipe document: those in the build
// (script and env) and those in the test block.
func scriptFetches(doc map[string]any) (build, test []string) {
	switch b := doc["build"].(type) {
	case map[string]any:
		build = append(fetchLines(b["script"]), fetchLines(b["env"])...)
	case nil:
	default:
		build = fetchLines(b) // a scalar script
	}
	return build, fetchLines(doc["test"])
}

// shapeSummary renders "3 archive, 1 patch" in a fixed order.
func shapeSummary(lines []string) string {
	n := map[string]int{}
	for _, l := range lines {
		n[fetchShape(l)]++
	}
	var parts []string
	for _, s := range []string{"floating", "patch", "archive", "other"} {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	return strings.Join(parts, ", ")
}
