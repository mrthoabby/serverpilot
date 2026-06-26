package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/mrthoabby/serverpilot/internal/sysinfo"
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
	ID                string         `json:"id"`
	Mode              PruneMode      `json:"mode"`
	Status            PruneJobStatus `json:"status"`
	Output            string         `json:"output,omitempty"`
	Error             string         `json:"error,omitempty"`
	StartedAt         time.Time      `json:"started_at"`
	FinishedAt        *time.Time     `json:"finished_at,omitempty"`
	BaselineReclaimMB float64        `json:"baseline_reclaim_mb,omitempty"`
	CurrentReclaimMB  float64        `json:"current_reclaim_mb,omitempty"`
	FreedMB           float64        `json:"freed_mb,omitempty"`
	FreedGB           float64        `json:"freed_gb,omitempty"`
	ProgressPercent   float64        `json:"progress_percent,omitempty"`
	ElapsedSeconds    int            `json:"elapsed_seconds,omitempty"`
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
	if snap := currentReclaimSnapshot(); snap != nil {
		baselineMB, _, _ := snap.EstimatePruneReclaim(mode)
		job.BaselineReclaimMB = baselineMB
		job.CurrentReclaimMB = baselineMB
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchPruneProgress(ctx, job)

	result, err := RunPrune(job.Mode)
	cancel()

	pruneJobsMu.Lock()
	defer pruneJobsMu.Unlock()

	now := time.Now()
	job.FinishedAt = &now
	job.ElapsedSeconds = int(now.Sub(job.StartedAt).Seconds())
	if err != nil {
		job.Status = PruneJobFailed
		job.Error = "docker prune failed"
	} else {
		job.Status = PruneJobCompleted
		job.Output = result.Output
		job.ProgressPercent = 100
		if snap := currentReclaimSnapshot(); snap != nil {
			currentMB, _, _ := snap.EstimatePruneReclaim(job.Mode)
			job.CurrentReclaimMB = currentMB
			updatePruneJobProgressLocked(job, currentMB)
		}
		if job.BaselineReclaimMB > 0 && job.FreedMB <= 0 {
			job.FreedMB = job.BaselineReclaimMB
			job.FreedGB = math.Round(job.FreedMB/1024*100) / 100
		}
	}
	if activePrune == job.ID {
		activePrune = ""
	}
	pruneTrimOldJobsLocked()
}

func watchPruneProgress(ctx context.Context, job *PruneJob) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruneJobsMu.Lock()
			if job.Status != PruneJobRunning {
				pruneJobsMu.Unlock()
				return
			}
			if snap := currentReclaimSnapshot(); snap != nil {
				currentMB, _, _ := snap.EstimatePruneReclaim(job.Mode)
				updatePruneJobProgressLocked(job, currentMB)
			} else {
				job.ElapsedSeconds = int(time.Since(job.StartedAt).Seconds())
			}
			pruneJobsMu.Unlock()
		}
	}
}

func currentReclaimSnapshot() *ReclaimSnapshot {
	rows := readReclaimRows()
	if len(rows) == 0 {
		return nil
	}
	snap := BuildReclaimSnapshot(rows)
	return &snap
}

func readReclaimRows() []ReclaimRow {
	stats := sysinfo.ReadDockerDiskInfo()
	if len(stats) == 0 {
		return nil
	}
	rows := make([]ReclaimRow, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, ReclaimRow{Type: s.Type, ReclaimMB: s.ReclaimMB})
	}
	return rows
}

func updatePruneJobProgressLocked(job *PruneJob, currentMB float64) {
	job.CurrentReclaimMB = currentMB
	job.ElapsedSeconds = int(time.Since(job.StartedAt).Seconds())

	freed := job.BaselineReclaimMB - currentMB
	if freed < 0 {
		freed = 0
	}
	job.FreedMB = math.Round(freed*100) / 100
	job.FreedGB = math.Round(job.FreedMB/1024*100) / 100

	if job.BaselineReclaimMB > 0 {
		pct := (freed / job.BaselineReclaimMB) * 100
		if pct > 99 && job.Status == PruneJobRunning {
			pct = 99
		}
		if pct > 100 {
			pct = 100
		}
		job.ProgressPercent = math.Round(pct*10) / 10
	}
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
