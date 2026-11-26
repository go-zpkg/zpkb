//go:build !windows

package main

import (
	"io"
	"os"
)

// seedPipeSupported proves what the provisioner relies on: that a pipe can be
// made here and carries a byte from its write end to its read end. The ledger
// reaches the child as an inherited descriptor, so nothing about the
// filesystem (a /dev/fd that is missing, or one somebody made) is involved and
// nothing of it is checked.
func seedPipeSupported() error {
	return probePipe(func() (io.ReadCloser, io.WriteCloser, error) { return os.Pipe() })
}

func probePipe(mk func() (io.ReadCloser, io.WriteCloser, error)) error {
	r, w, err := mk()
	if err != nil {
		return err
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.Write([]byte{'x'}); err != nil {
		return err
	}
	var b [1]byte
	_, err = io.ReadFull(r, b[:])
	return err
}
