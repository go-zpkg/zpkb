package main

import (
	"fmt"
	"io"

	"github.com/go-zpkg/artifact"
)

// installWarnSink makes the artifact library's non-fatal diagnostics visible.
// Until it was set, a registry GET that failed and was retried (go-zpkg/artifact
// retries manifest and referrer reads on a timeout or a 429/5xx) left no trace:
// the run was slower and nobody could say why. An existing sink is kept.
func installWarnSink(w io.Writer) {
	if artifact.Warn != nil {
		return
	}
	artifact.Warn = func(msg string) { fmt.Fprintln(w, "zpkb: "+msg) }
}
