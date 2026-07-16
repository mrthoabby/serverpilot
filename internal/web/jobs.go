package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mrthoabby/serverpilot/internal/docker"
)

// Background-job tracking.
//
// Several dashboard operations (replica create/sync/delete, SSL enable/disable,
// site delete, domain update, www alias, GD-App activate, dependency install)
// are long-running and streamed to the browser over Server-Sent Events. If the
// operator closes the progress modal or the browser tab, the server goroutine
// keeps running to completion but the UI loses all visibility.
//
// The registry below tees every SSE frame into a bounded in-memory buffer keyed
// by an unguessable job id, so the dashboard can list running/finished jobs and
// reconnect to their log stream. It never kills a running operation: privileged,
// multi-step operations can leave nginx/certs/containers in a half-applied state
// if interrupted, so the only client action offered is "stop following" / dismiss.
//
// Memory is intentionally bounded (a small number of finished jobs, a capped log
// buffer per job, and truncated lines) to stay within the daemon's footprint.

type jobStatus string

const (
	jobRunning   jobStatus = "running"
	jobCompleted jobStatus = "completed"
	jobFailed    jobStatus = "failed"
)

const (
	jobMaxLogLines   = 400  // per job; caps memory even for chatty operations
	jobMaxFinished   = 30   // finished jobs retained for post-hoc inspection
	jobLogLineMaxLen = 2000 // defensive cap on a single log line
)

// logEntry is a single buffered SSE log line with a monotonic sequence used by
// clients to request only the lines they have not seen yet.
type logEntry struct {
	Seq  int    `json:"seq"`
	Line string `json:"line"`
}

// backgroundJob is an in-flight or recently finished tracked operation.
type backgroundJob struct {
	mu         sync.Mutex
	id         string
	kind       string
	title      string
	subtitle   string
	status     jobStatus
	errMsg     string
	startedAt  time.Time
	finishedAt time.Time
	seq        int
	logs       []logEntry
}

// jobSnapshot is the read-only JSON view returned to the dashboard.
type jobSnapshot struct {
	ID              string     `json:"id"`
	Kind            string     `json:"kind"`
	Title           string     `json:"title"`
	Subtitle        string     `json:"subtitle,omitempty"`
	Status          string     `json:"status"`
	Error           string     `json:"error,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ElapsedSeconds  int        `json:"elapsed_seconds"`
	ProgressPercent float64    `json:"progress_percent,omitempty"`
	LogCount        int        `json:"log_count"`
	Source          string     `json:"source"`
}

// jobTailResult is returned by the tail endpoint so a reconnecting client can
// catch up on missed log lines and learn the final status.
type jobTailResult struct {
	ID       string     `json:"id"`
	Status   string     `json:"status"`
	Error    string     `json:"error,omitempty"`
	Logs     []logEntry `json:"logs"`
	NextSeq  int        `json:"next_seq"`
	Finished bool       `json:"finished"`
}

type jobRegistry struct {
	mu   sync.RWMutex
	jobs map[string]*backgroundJob
}

func newJobRegistry() *jobRegistry {
	return &jobRegistry{jobs: make(map[string]*backgroundJob)}
}

func newJobID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a timestamp-derived id; collisions are practically
		// impossible for the small number of concurrent jobs we track.
		return fmt.Sprintf("j%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// start registers a new running job and returns it.
func (r *jobRegistry) start(kind, title, subtitle string) *backgroundJob {
	job := &backgroundJob{
		id:        newJobID(),
		kind:      kind,
		title:     title,
		subtitle:  subtitle,
		status:    jobRunning,
		startedAt: time.Now(),
	}
	r.mu.Lock()
	r.jobs[job.id] = job
	r.trimLocked()
	r.mu.Unlock()
	return job
}

func (r *jobRegistry) get(id string) (*backgroundJob, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	job, ok := r.jobs[id]
	return job, ok
}

// dismiss removes a finished job. Running jobs are never removed here so that a
// backgrounded operation stays observable until it actually completes.
func (r *jobRegistry) dismiss(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	job, ok := r.jobs[id]
	if !ok {
		return false
	}
	job.mu.Lock()
	running := job.status == jobRunning
	job.mu.Unlock()
	if running {
		return false
	}
	delete(r.jobs, id)
	return true
}

func (r *jobRegistry) snapshots() []jobSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]jobSnapshot, 0, len(r.jobs))
	for _, job := range r.jobs {
		out = append(out, job.snapshot())
	}
	return out
}

// trimLocked drops the oldest finished jobs beyond jobMaxFinished. Callers must
// hold r.mu.
func (r *jobRegistry) trimLocked() {
	type entry struct {
		id string
		at time.Time
	}
	var finished []entry
	for id, job := range r.jobs {
		job.mu.Lock()
		done := job.status != jobRunning
		at := job.finishedAt
		job.mu.Unlock()
		if done {
			finished = append(finished, entry{id: id, at: at})
		}
	}
	if len(finished) <= jobMaxFinished {
		return
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].at.Before(finished[j].at) })
	for i := 0; i < len(finished)-jobMaxFinished; i++ {
		delete(r.jobs, finished[i].id)
	}
}

func (j *backgroundJob) appendLog(line string) {
	if len(line) > jobLogLineMaxLen {
		line = line[:jobLogLineMaxLen]
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	j.logs = append(j.logs, logEntry{Seq: j.seq, Line: line})
	if len(j.logs) > jobMaxLogLines {
		j.logs = append(j.logs[:0], j.logs[len(j.logs)-jobMaxLogLines:]...)
	}
}

func (j *backgroundJob) finish(success bool, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status != jobRunning {
		return
	}
	j.finishedAt = time.Now()
	if success {
		j.status = jobCompleted
	} else {
		j.status = jobFailed
		j.errMsg = sanitizeLogField(errMsg, 240)
	}
}

// finishIfAbandoned marks a still-running job as failed. It is deferred by SSE
// handlers so that an early return or a panic (recovered by the recovery
// middleware) does not leave a phantom "running" job forever.
func (j *backgroundJob) finishIfAbandoned() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status != jobRunning {
		return
	}
	j.finishedAt = time.Now()
	j.status = jobFailed
	j.errMsg = "operation ended unexpectedly"
}

// record is called from sseWriteEvent for every framed event on a teed writer.
func (j *backgroundJob) record(event, data string) {
	switch event {
	case "log":
		var line string
		if err := json.Unmarshal([]byte(data), &line); err != nil {
			line = data
		}
		j.appendLog(line)
	case "done":
		var res struct {
			Success *bool  `json:"success"`
			Error   string `json:"error"`
		}
		success := true
		errMsg := ""
		if err := json.Unmarshal([]byte(data), &res); err == nil {
			if res.Success != nil {
				success = *res.Success
			}
			errMsg = res.Error
		}
		j.finish(success, errMsg)
	}
}

func (j *backgroundJob) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	snap := jobSnapshot{
		ID:        j.id,
		Kind:      j.kind,
		Title:     j.title,
		Subtitle:  j.subtitle,
		Status:    string(j.status),
		Error:     j.errMsg,
		StartedAt: j.startedAt,
		LogCount:  len(j.logs),
		Source:    "stream",
	}
	if !j.finishedAt.IsZero() {
		ft := j.finishedAt
		snap.FinishedAt = &ft
		snap.ElapsedSeconds = int(ft.Sub(j.startedAt).Seconds())
	} else {
		snap.ElapsedSeconds = int(time.Since(j.startedAt).Seconds())
	}
	return snap
}

func (j *backgroundJob) tail(after int) jobTailResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	res := jobTailResult{
		ID:       j.id,
		Status:   string(j.status),
		Error:    j.errMsg,
		NextSeq:  j.seq,
		Finished: j.status != jobRunning,
	}
	for _, e := range j.logs {
		if e.Seq > after {
			res.Logs = append(res.Logs, e)
		}
	}
	return res
}

// ── SSE tee ──────────────────────────────────────────────────────────────────

// sseJobTee wraps the response writer used by an SSE handler so that every
// framed event written through sseWriteEvent is also recorded into the job
// registry. It preserves http.Flusher via the captured flusher.
type sseJobTee struct {
	http.ResponseWriter
	flusher http.Flusher
	job     *backgroundJob
}

func (t *sseJobTee) Flush() {
	if t.flusher != nil {
		t.flusher.Flush()
	}
}

func (t *sseJobTee) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// wrapSSE registers a job, announces its id to the client (so it can reconnect
// after closing the modal), and returns a teed writer. Handlers should call this
// once, after validating input and writing SSE headers, and defer
// job.finishIfAbandoned().
func (s *Server) wrapSSE(w http.ResponseWriter, flusher http.Flusher, kind, title, subtitle string) (http.ResponseWriter, *backgroundJob) {
	job := s.jobs.start(kind, title, subtitle)
	// The "job" frame is intentionally not recorded (it carries no log content).
	fmt.Fprintf(w, "event: job\ndata: %q\n\n", job.id)
	flusher.Flush()
	return &sseJobTee{ResponseWriter: w, flusher: flusher, job: job}, job
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

func pruneJobToSnapshot(pj *docker.PruneJob) jobSnapshot {
	snap := jobSnapshot{
		ID:              pj.ID,
		Kind:            "docker-prune",
		Title:           "Docker prune",
		Subtitle:        string(pj.Mode),
		Status:          string(pj.Status),
		Error:           pj.Error,
		StartedAt:       pj.StartedAt,
		FinishedAt:      pj.FinishedAt,
		ElapsedSeconds:  pj.ElapsedSeconds,
		ProgressPercent: pj.ProgressPercent,
		Source:          "docker-prune",
	}
	// docker.PruneJobStatus uses "running"; normalize to our vocabulary.
	if snap.Status == string(docker.PruneJobRunning) {
		snap.Status = string(jobRunning)
	} else if snap.Status == string(docker.PruneJobCompleted) {
		snap.Status = string(jobCompleted)
	} else if snap.Status == string(docker.PruneJobFailed) {
		snap.Status = string(jobFailed)
	}
	return snap
}

// handleJobsList returns every tracked job (streamed operations plus the docker
// prune bridge), running first and then most-recent finished.
func (s *Server) handleJobsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	snaps := s.jobs.snapshots()
	for _, pj := range docker.ListPruneJobs() {
		snaps = append(snaps, pruneJobToSnapshot(pj))
	}
	sort.Slice(snaps, func(i, j int) bool {
		ri := snaps[i].Status == string(jobRunning)
		rj := snaps[j].Status == string(jobRunning)
		if ri != rj {
			return ri // running jobs first
		}
		return snaps[i].StartedAt.After(snaps[j].StartedAt)
	})
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: snaps})
}

// handleJobTail returns log lines after ?after=<seq> for a streamed job, so a
// reconnecting client can catch up. Docker prune jobs are handled by their own
// status endpoint and are not tailed here.
func (s *Server) handleJobTail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "missing job id"})
		return
	}
	after := 0
	if v := strings.TrimSpace(r.URL.Query().Get("after")); v != "" {
		if n, err := parseNonNegativeInt(v); err == nil {
			after = n
		}
	}
	job, ok := s.jobs.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: job.tail(after)})
}

// handleJobDismiss removes a finished job from the tracked list. Running jobs
// cannot be dismissed (they stay observable until they finish); this endpoint
// never terminates the underlying operation.
func (s *Server) handleJobDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "missing job id"})
		return
	}
	if !s.jobs.dismiss(id) {
		writeJSON(w, http.StatusConflict, apiResponse{Error: "job is still running or not found"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

func parseNonNegativeInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 1 << 30, nil
		}
	}
	return n, nil
}
