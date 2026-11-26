//go:build !windows

package artifactpkg

import "syscall"

// setUmask sets the process umask and returns the previous one.
func setUmask(mask int) int { return syscall.Umask(mask) }
