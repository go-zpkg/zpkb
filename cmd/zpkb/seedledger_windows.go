//go:build windows

package main

import "errors"

// seedPipeSupported: a seed pass runs on the unix build hosts only, where an
// inherited descriptor carries the ledger.
func seedPipeSupported() error {
	return errors.New("a seed pass hands zpkx its ledger as an inherited descriptor, which this system does not provide")
}
