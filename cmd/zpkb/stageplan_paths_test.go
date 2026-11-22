package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishStageIsDispatchedByTheMainCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"publish-stage"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage: zpkb publish-stage") {
		t.Errorf("code %d: %s", code, errb.String())
	}
}

func TestStagePlanRefusesAFileThatIsNotATarball(t *testing.T) {
	e := guardEntry("a.org", "1.0", 0)
	e.File = "p0/v.zip"
	err := guardParse(t, guardPlan(e))
	if err == nil || !strings.Contains(err.Error(), "is not a .tar.gz, .tar.xz or .tar.zst") {
		t.Errorf("err = %v", err)
	}
}

func TestPublishStageTakesTheDirectoryAfterTheFlags(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	var out, errb bytes.Buffer
	code := runPublishStage([]string{"--to", stageDist, "--allow-unsigned", r.h.artifacts}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "2 published, 0 failed") {
		t.Errorf("code %d\n%s\n%s", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	code = runPublishStage([]string{"--to", stageDist, "--allow-unsigned", r.h.artifacts, "another"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "usage: zpkb publish-stage") {
		t.Errorf("two directories: code %d: %s", code, errb.String())
	}
}

func TestPublishStageWarnsOfAPlanFromAnotherBuilder(t *testing.T) {
	r := newStageRig(t)
	plan := r.stage(t)
	data, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	was, _ := json.Marshal(builderWithVersion())
	now, _ := json.Marshal("older-zpkb 0.0.1")
	if !bytes.Contains(data, was) {
		t.Fatalf("the plan does not name its builder as %s", was)
	}
	if err := os.WriteFile(plan, bytes.Replace(data, was, now, 1), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, e := r.publishStage("--to", stageDist, "--allow-unsigned")
	if code != 0 || !strings.Contains(e, "warning: plan written by older-zpkb 0.0.1") {
		t.Errorf("code %d: %s", code, e)
	}
}

func TestPublishStageAnnouncesARepairedIndex(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	withEnsurer(t, &fakeEnsurer{repairAll: true}, nil)
	code, out, e := r.publishStage("--to", stageDist, "--allow-unsigned")
	if code != 0 || !strings.Contains(out, "index(es) repaired") {
		t.Errorf("code %d\n%s\n%s", code, out, e)
	}
}

// The file is read once to check everything before the first push and once more
// to push what was checked. A read that fails the second time (the file changed
// in between) fails that artifact and not the others.
func TestPublishStageCountsAnArtifactThatCannotBeReadAgain(t *testing.T) {
	r := newStageRig(t)
	r.stage(t)
	old := stageReadAll
	t.Cleanup(func() { stageReadAll = old })
	calls := 0
	stageReadAll = func(f *os.File, limit int64) ([]byte, error) {
		calls++
		if calls == 3 { // the first two are the checks, the third is the first push
			return nil, errors.New("changed under us")
		}
		return old(f, limit)
	}
	code, out, e := r.publishStage("--to", stageDist, "--allow-unsigned")
	if code != 1 || !strings.Contains(e, "changed under us") || !strings.Contains(out, "1 published, 1 failed") {
		t.Errorf("code %d\n%s\n%s", code, out, e)
	}
	if len(r.pushes) != 1 {
		t.Errorf("%d pushes, want only the artifact that could be read", len(r.pushes))
	}
	if _, err := os.Stat(filepath.Join(r.h.artifacts, stagePlanName)); err != nil {
		t.Error(err)
	}
}
