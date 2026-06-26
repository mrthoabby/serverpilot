package docker

import (
	"testing"
	"time"
)

func TestStartPruneJobRejectsConcurrent(t *testing.T) {
	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{}
	activePrune = ""
	pruneJobsMu.Unlock()

	id, err := newPruneJobID()
	if err != nil {
		t.Fatal(err)
	}

	pruneJobsMu.Lock()
	pruneJobs[id] = &PruneJob{ID: id, Mode: PruneBuilder, Status: PruneJobRunning, StartedAt: time.Now()}
	activePrune = id
	pruneJobsMu.Unlock()

	_, err = StartPruneJob(PruneBuilder)
	if err != ErrPruneAlreadyRunning {
		t.Fatalf("expected ErrPruneAlreadyRunning, got %v", err)
	}

	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{}
	activePrune = ""
	pruneJobsMu.Unlock()
}

func TestGetPruneJobClone(t *testing.T) {
	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{
		"abc": {ID: "abc", Mode: PruneSafe, Status: PruneJobCompleted, Output: "done"},
	}
	pruneJobsMu.Unlock()

	got, ok := GetPruneJob("abc")
	if !ok || got.Output != "done" {
		t.Fatalf("unexpected job snapshot: %+v ok=%v", got, ok)
	}
	got.Output = "mutated"
	again, _ := GetPruneJob("abc")
	if again.Output != "done" {
		t.Fatal("GetPruneJob should return a clone")
	}

	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{}
	activePrune = ""
	pruneJobsMu.Unlock()
}

func TestUpdatePruneJobProgressLocked(t *testing.T) {
	job := &PruneJob{
		Mode:              PruneBuilder,
		Status:            PruneJobRunning,
		BaselineReclaimMB: 65000,
		StartedAt:         time.Now().Add(-30 * time.Second),
	}
	updatePruneJobProgressLocked(job, 30000)
	if job.FreedMB != 35000 {
		t.Fatalf("freed mb = %v, want 35000", job.FreedMB)
	}
	if job.ProgressPercent != 53.8 {
		t.Fatalf("progress = %v, want 53.8", job.ProgressPercent)
	}
	if job.ElapsedSeconds < 29 {
		t.Fatalf("elapsed = %d, want >= 29", job.ElapsedSeconds)
	}
}

func TestActivePruneJob(t *testing.T) {
	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{}
	activePrune = ""
	pruneJobsMu.Unlock()

	if _, ok := ActivePruneJob(); ok {
		t.Fatal("expected no active job")
	}

	pruneJobsMu.Lock()
	pruneJobs["run1"] = &PruneJob{ID: "run1", Mode: PruneBuilder, Status: PruneJobRunning, StartedAt: time.Now()}
	activePrune = "run1"
	pruneJobsMu.Unlock()

	job, ok := ActivePruneJob()
	if !ok || job.ID != "run1" {
		t.Fatalf("expected active job run1, got %+v ok=%v", job, ok)
	}

	pruneJobsMu.Lock()
	pruneJobs = map[string]*PruneJob{}
	activePrune = ""
	pruneJobsMu.Unlock()
}
