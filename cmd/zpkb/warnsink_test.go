package main

import (
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

func TestInstallWarnSinkWritesArtifactWarnings(t *testing.T) {
	old := artifact.Warn
	t.Cleanup(func() { artifact.Warn = old })
	artifact.Warn = nil

	var b strings.Builder
	installWarnSink(&b)
	if artifact.Warn == nil {
		t.Fatal("artifact.Warn was not set")
	}
	artifact.Warn("retrying")
	if got := b.String(); got != "zpkb: retrying\n" {
		t.Errorf("sink wrote %q", got)
	}

	// A sink someone already set is theirs.
	var other strings.Builder
	artifact.Warn = func(m string) { other.WriteString(m) }
	installWarnSink(&b)
	artifact.Warn("x")
	if other.String() != "x" {
		t.Errorf("existing sink was replaced: %q", other.String())
	}
}
