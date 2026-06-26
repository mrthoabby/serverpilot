package docker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PruneJobStatus tracks async docker prune execution.
type PruneJobStatus string

const (
	PruneJobRunning   PruneJobStatus = "running"
	PruneJobCompleted PruneJobStatus = "completed"
	PruneJobFailed    PruneJobStatus = "failed"
)

var ErrPruneAlreadyRunning = errors.New("prune already running")

// PruneJob is an in-flight or recently finished docker prune operation.
type PruneJob struct {
	ID         string         `json:"id"`
	Mode       PruneMode      `json:"mode"`
	Status     PruneJobStatus `json:"status"`
	Output     string         `json:"output,omitempty"`
	Error      string         `json:"error,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

var (
	pruneJobsMu sync.RWMutex
	pruneJobs   = map[string]*PruneJob{}
	activePrune string
)

// StartPruneJob runs docker prune in the background and returns immediately.
func StartPruneJob(mode PruneMode) (*PruneJob, error) {
	if !mode.Valid() {
		return nil, fmt.Errorf("invalid prune mode")
	}

	pruneJobsMu.Lock()
	defer pruneJobsMu.Unlock()

	if activePrune != "" {
		if job, ok := pruneJobs[activePrune]; ok && job.Status == PruneJobRunning {
			return nil, ErrPruneAlreadyRunning
		}
	}

	id, err := newPruneJobID()
	if err != nil {
		return nil, fmt.Errorf("failed to start prune job")
	}

	job := &PruneJob{
		ID:        id,
		Mode:      mode,
		Status:    PruneJobRunning,
		StartedAt: time.Now(),
	}
	pruneJobs[id] = job
	activePrune = id

	go runPruneJob(job)
	return clonePruneJob(job), nil
}

// GetPruneJob returns a job snapshot by id.
func GetPruneJob(id string) (*PruneJob, bool) {
	pruneJobsMu.RLock()
	defer pruneJobsMu.RUnlock()
	job, ok := pruneJobs[id]
	if !ok {
		return nil, false
	}
	return clonePruneJob(job), true
}

// ActivePruneJob returns the currently running prune job, if any.
func ActivePruneJob() (*PruneJob, bool) {
	pruneJobsMu.RLock()
	defer pruneJobsMu.RUnlock()
	if activePrune == "" {
		return nil, false
	}
	job, ok := pruneJobs[activePrune]
	if !ok || job.Status != PruneJobRunning {
		return nil, false
	}
	return clonePruneJob(job), true
}

func runPruneJob(job *PruneJob) {
	result, err := RunPrune(job.Mode)

	pruneJobsMu.Lock()
	defer pruneJobsMu.Unlock()

	now := time.Now()
	job.FinishedAt = &now
	if err != nil {
		job.Status = PruneJobFailed
		job.Error = "docker prune failed"
	} else {
		job.Status = PruneJobCompleted
		job.Output = result.Output
	}
	if activePrune == job.ID {
		activePrune = ""
	}
	pruneTrimOldJobsLocked()
}

func pruneTrimOldJobsLocked() {
	const keep = 10
	if len(pruneJobs) <= keep {
		return
	}
	type entry struct {
		id string
		at time.Time
	}
	var finished []entry
	for id, job := range pruneJobs {
		if job.Status == PruneJobRunning {
			continue
		}
		at := job.StartedAt
		if job.FinishedAt != nil {
			at = *job.FinishedAt
		}
		finished = append(finished, entry{id: id, at: at})
	}
	if len(finished) <= keep {
		return
	}
	// Drop oldest finished jobs beyond keep limit.
	for i := 0; i < len(finished)-1; i++ {
		for j := i + 1; j < len(finished); j++ {
			if finished[j].at.Before(finished[i].at) {
				finished[i], finished[j] = finished[j], finished[i]
			}
		}
	}
	for i := keep; i < len(finished); i++ {
		delete(pruneJobs, finished[i].id)
	}
}

func newPruneJobID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func clonePruneJob(job *PruneJob) *PruneJob {
	if job == nil {
		return nil
	}
	copy := *job
	return &copy
}
