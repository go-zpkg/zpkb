package main

import (
	"fmt"
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
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if st == nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	var names []string
	err = fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, p)
		}
		return nil
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
