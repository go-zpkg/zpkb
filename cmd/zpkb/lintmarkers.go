package main

import (
	"io/fs"
	"os"
	"sort"
)

// readMarkers returns the recipe names a --fragments-dir holds: the path of
// every regular file under dir, relative to it and slash-separated, so a nested
// recipe name such as crates.io/gitui comes back whole. A directory that does
// not exist, is not a directory, or cannot be read is an error, never an empty
// or partial set: a list that could not be read would otherwise read as "no
// fragments are tolerated" or, worse, as a pass.
func readMarkers(dir string) ([]string, error) {
	// fs.WalkDir stats the root first, so a missing path and a plain file both
	// come back as the walk's own error ("no such file", "not a directory").
	var names []string
	err := fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		// d is nil when the root itself could not be read, hence err first.
		if err == nil && !d.IsDir() {
			names = append(names, p)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// diffMarkers compares the fragments the tree has with the markers it states.
// regress are fragments without a marker; stale are markers whose recipe is
// not a fragment (whole, or gone). Both come back sorted.
func diffMarkers(fragments, markers []string) (regress, stale []string) {
	have := make(map[string]bool, len(fragments))
	for _, f := range fragments {
		have[f] = true
	}
	stated := make(map[string]bool, len(markers))
	for _, m := range markers {
		stated[m] = true
		if !have[m] {
			stale = append(stale, m)
		}
	}
	for _, f := range fragments {
		if !stated[f] {
			regress = append(regress, f)
		}
	}
	sort.Strings(regress)
	sort.Strings(stale)
	return regress, stale
}
