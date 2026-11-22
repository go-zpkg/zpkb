package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A guard that returns early on an error protects the code after it from a nil
// value. Without the guard that code panics, and a suite that is red by panic
// has said nothing about what the guard is for. Each case here runs the refusal
// under a recover that turns a panic into a failed assertion naming the guard,
// and asserts the reason the refusal gives.

func refusesWithoutPanic(t *testing.T, guard string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: the guard is missing, the code after it panicked: %v", guard, r)
		}
	}()
	f()
}

func TestGuardsThatProtectANilAreHeldByAnAssertion(t *testing.T) {
	dir := t.TempDir()
	p := guardPlan()

	// loadStagePlan: an existing plan that does not parse.
	bad := filepath.Join(dir, "bad")
	if err := os.Mkdir(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, stagePlanName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	refusesWithoutPanic(t, "loadStagePlan parse", func() {
		_, err := loadStagePlan(bad, "oci://x/y", "linux/x86-64", time.Unix(1, 0))
		if err == nil || !strings.Contains(err.Error(), "not one this run can extend") {
			t.Errorf("loadStagePlan parse: %v", err)
		}
	})

	// writeStagePlan: the temporary file cannot be created.
	if os.Getuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		refusesWithoutPanic(t, "writeStagePlan CreateTemp", func() {
			err := writeStagePlan(ro, &p)
			if err == nil || !errors.Is(err, fs.ErrPermission) {
				t.Errorf("writeStagePlan CreateTemp: %v", err)
			}
		})
	}

	// readStaged: stat fails.
	if err := os.WriteFile(filepath.Join(dir, "a.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	boom := errors.New("injected stat")
	old := stageStat
	t.Cleanup(func() { stageStat = old })
	stageStat = func(*os.File) (fs.FileInfo, error) { return nil, boom }
	refusesWithoutPanic(t, "readStaged stat", func() {
		_, err := readStaged(root, stageEntry{File: "a.tar.gz", Size: 1})
		if !errors.Is(err, boom) {
			t.Errorf("readStaged stat: %v", err)
		}
	})
	stageStat = old

	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		return runPublishStage(args, &out, &errb), errb.String()
	}
	to := []string{"--to", stageDist, "--allow-unsigned"}

	// runPublishStage: the stage directory cannot be opened as a root.
	refusesWithoutPanic(t, "runPublishStage OpenRoot", func() {
		code, e := run(append([]string{filepath.Join(dir, "none")}, to...)...)
		if code != 1 || !strings.Contains(e, "publish-stage: ") || !strings.Contains(e, "no such file") {
			t.Errorf("runPublishStage OpenRoot: %d %q", code, e)
		}
	})

	// runPublishStage: the plan does not parse.
	refusesWithoutPanic(t, "runPublishStage parse", func() {
		code, e := run(append([]string{bad}, to...)...)
		if code != 1 || !strings.HasPrefix(e, "publish-stage: ") || strings.Contains(e, "no such file") {
			t.Errorf("runPublishStage parse: %d %q", code, e)
		}
		if !strings.Contains(e, "invalid") {
			t.Errorf("runPublishStage parse: the reason is not the parser's: %q", e)
		}
	})
}
