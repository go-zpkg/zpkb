package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// seedTarget is one installed artifact: <project>/v<version> under a root, the
// layout zpkb builds and zpkx installs (project names carry slashes).
type seedTarget struct {
	path             string
	project, version string
}

// isVersionDir says a directory name is the v<version> of an install: a v and
// a digit. A project such as v8.dev also fits, so seedTargets keeps only the
// DEEPEST such directory of a chain.
func isVersionDir(name string) bool {
	return len(name) > 1 && name[0] == 'v' && name[1] >= '0' && name[1] <= '9'
}

// seedTargets lists every <project>/v<version> under root. An empty answer is an
// error: a batch check that finds nothing to check would pass for the wrong
// reason, and "no artifact was installed" is not "every artifact was seed-built".
func seedTargets(root string) ([]seedTarget, error) {
	root = filepath.Clean(root)
	var cands []seedTarget
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || p == root || !isVersionDir(d.Name()) {
			return nil
		}
		parent := strings.Trim(strings.TrimPrefix(filepath.Dir(p), root), string(filepath.Separator))
		if parent == "" {
			return nil // directly under the root: a project, not a version
		}
		cands = append(cands, seedTarget{path: p, project: filepath.ToSlash(parent), version: d.Name()[1:]})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	var out []seedTarget
	for _, c := range cands {
		inner := false
		for _, o := range cands {
			if strings.HasPrefix(o.path, c.path+string(filepath.Separator)) {
				inner = true
			}
		}
		if !inner {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no <project>/v<version> directory under %s: nothing to verify, and that is not a pass", root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// verifySeededRoot is `origin --seeded --root`: every artifact under root must
// carry a verified seed claim. One refusal fails the whole, and every refusal
// is listed, so a pass-2 run names all that are wrong at once.
func verifySeededRoot(dist, root, osn, arch, want string, stderr io.Writer) int {
	ts, err := seedTargets(root)
	if err != nil {
		fmt.Fprintln(stderr, "origin:", err)
		return 1
	}
	var errs []error
	for _, t := range ts {
		if _, err := verifiedSeed(dist, t.project, t.version, osn, arch, want); err != nil {
			errs = append(errs, fmt.Errorf("%s %s (%s/%s): %v", t.project, t.version, osn, arch, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		fmt.Fprintf(stderr, "origin: %d of %d artifacts are not verifiably seed-built:\n%v\n", len(errs), len(ts), err)
		return 1
	}
	return 0
}
