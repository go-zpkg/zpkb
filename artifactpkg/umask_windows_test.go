//go:build windows

package artifactpkg

// setUmask: Windows has no umask; the artifact is still normalised, so the
// two builds the test compares come out identical.
func setUmask(mask int) int { return mask }
