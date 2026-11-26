//go:build !windows

package main

// seedPipeSupported says whether a child can open the ledger pipe as /dev/fd/3.
func seedPipeSupported() error { return nil }
