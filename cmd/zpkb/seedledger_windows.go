//go:build windows

package main

import "errors"

// seedPipeSupported: a seed pass runs on the unix build hosts only.
func seedPipeSupported() error {
	return errors.New("a seed pass needs /dev/fd, which this system does not have")
}
