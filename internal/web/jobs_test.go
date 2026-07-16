package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer() *Server {
	return &Server{jobs: newJobRegistry()}
}

func TestJobRegistryLifecycle(t *testing.T) {
	r := newJobRegistry()
	job := r.start("ssl-enable", "Enabling SSL", "example.com")
	if job.id == "" {
		t.Fatal("expected non-empty job id")
	}
	snap := job.snapshot()
	if snap.Status != string(jobRunning) {
		t.Fatalf("status = %q, want running", snap.Status)
	}

	job.appendLog("line one")
	job.appendLog("line two")
	tail := job.tail(0)
	if len(tail.Logs) != 2 {
		t.Fatalf("tail returned %d logs, want 2", len(tail.Logs))
	}
	if tail.Finished {
		t.Fatal("job should not be finished yet")
	}

	// Incremental tail returns only newer lines.
	partial := job.tail(tail.Logs[0].Seq)
	if len(partial.Logs) != 1 || partial.Logs[0].Line != "line two" {
		t.Fatalf("incremental tail = %+v, want only 'line two'", partial.Logs)
	}

	job.finish(true, "")
	if snap := job.snapshot(); snap.Status != string(jobCompleted) {
		t.Fatalf("status = %q, want completed", snap.Status)
	}
	if snap := job.snapshot(); snap.FinishedAt == nil {
		t.Fatal("expected FinishedAt to be set")
	}

	if !r.dismiss(job.id) {
		t.Fatal("expected finished job to be dismissable")
	}
	if _, ok := r.get(job.id); ok {
		t.Fatal("job should be gone after dismiss")
	}
}

func TestJobRegistryCannotDismissRunning(t *testing.T) {
	r := newJobRegistry()
	job := r.start("site-delete", "Deleting site", "example.com")
	if r.dismiss(job.id) {
		t.Fatal("running job must not be dismissable")
	}
	if _, ok := r.get(job.id); !ok {
		t.Fatal("running job should still be tracked")
	}
}

func TestJobFinishIsIdempotent(t *testing.T) {
	r := newJobRegistry()
	job := r.start("gdapp-activate", "Activating GD-App", "example.com")
	job.finish(false, "boom")
	first := job.snapshot()
	job.finish(true, "") // should be a no-op
	second := job.snapshot()
	if first.Status != string(jobFailed) || second.Status != string(jobFailed) {
		t.Fatalf("status changed after first finish: %q -> %q", first.Status, second.Status)
	}
	if second.Error != "boom" {
		t.Fatalf("error = %q, want boom", second.Error)
	}
}

func TestJobLogBufferBounded(t *testing.T) {
	r := newJobRegistry()
	job := r.start("dependency-install", "Installing certbot", "certbot")
	total := jobMaxLogLines + 50
	for i := 0; i < total; i++ {
		job.appendLog("l")
	}
	tail := job.tail(0)
	if len(tail.Logs) != jobMaxLogLines {
		t.Fatalf("buffered %d logs, want cap %d", len(tail.Logs), jobMaxLogLines)
	}
	// Sequence numbers keep advancing even after trimming.
	if tail.Logs[len(tail.Logs)-1].Seq != total {
		t.Fatalf("last seq = %d, want %d", tail.Logs[len(tail.Logs)-1].Seq, total)
	}
}

func TestJobRegistryTrimKeepsRunning(t *testing.T) {
	r := newJobRegistry()
	running := r.start("ssl-enable", "Enabling SSL", "keep.example.com")
	for i := 0; i < jobMaxFinished+15; i++ {
		j := r.start("site-delete", "Deleting site", "x")
		j.finish(true, "")
	}
	r.mu.Lock()
	r.trimLocked()
	count := len(r.jobs)
	r.mu.Unlock()
	if count > jobMaxFinished+1 {
		t.Fatalf("registry kept %d jobs, want <= %d", count, jobMaxFinished+1)
	}
	if _, ok := r.get(running.id); !ok {
		t.Fatal("running job must survive trimming")
	}
}

func TestSSEWriteEventRecordsIntoJob(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	tee, job := s.wrapSSE(rec, rec, "ssl-enable", "Enabling SSL", "example.com")

	sseWriteLog(tee, rec, "hello")
	sseWriteDone(tee, rec, map[string]interface{}{"success": false, "error": "nope"})

	tail := job.tail(0)
	if len(tail.Logs) != 1 || tail.Logs[0].Line != "hello" {
		t.Fatalf("expected one recorded log 'hello', got %+v", tail.Logs)
	}
	if snap := job.snapshot(); snap.Status != string(jobFailed) || snap.Error != "nope" {
		t.Fatalf("snapshot = %+v, want failed/nope", snap)
	}
	// The announce frame plus the streamed frames should have hit the wire.
	if !strings.Contains(rec.Body.String(), "event: job") {
		t.Fatal("expected job announce frame in SSE output")
	}
}

func TestHandleJobsListAndDismiss(t *testing.T) {
	s := newTestServer()
	job := s.jobs.start("ssl-enable", "Enabling SSL", "example.com")
	job.finish(true, "")

	req := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
	rec := httptest.NewRecorder()
	s.handleJobsList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var listResp struct {
		Success bool          `json:"success"`
		Data    []jobSnapshot `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Data) == 0 {
		t.Fatal("expected at least one job in list")
	}

	body := strings.NewReader(`{"id":"` + job.id + `"}`)
	dreq := httptest.NewRequest(http.MethodPost, "/api/jobs/dismiss", body)
	drec := httptest.NewRecorder()
	s.handleJobDismiss(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("dismiss status = %d, body=%s", drec.Code, drec.Body.String())
	}
	if _, ok := s.jobs.get(job.id); ok {
		t.Fatal("job should be dismissed")
	}
}

func TestHandleJobDismissRunningConflict(t *testing.T) {
	s := newTestServer()
	job := s.jobs.start("site-delete", "Deleting site", "example.com")
	body := strings.NewReader(`{"id":"` + job.id + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/jobs/dismiss", body)
	rec := httptest.NewRecorder()
	s.handleJobDismiss(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dismiss running status = %d, want 409", rec.Code)
	}
}

func TestHandleJobTail(t *testing.T) {
	s := newTestServer()
	job := s.jobs.start("dependency-install", "Installing certbot", "certbot")
	job.appendLog("a")
	job.appendLog("b")

	req := httptest.NewRequest(http.MethodGet, "/api/jobs/tail?id="+job.id+"&after=1", nil)
	rec := httptest.NewRecorder()
	s.handleJobTail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tail status = %d", rec.Code)
	}
	var resp struct {
		Success bool          `json:"success"`
		Data    jobTailResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode tail: %v", err)
	}
	if len(resp.Data.Logs) != 1 || resp.Data.Logs[0].Line != "b" {
		t.Fatalf("tail after=1 = %+v, want only 'b'", resp.Data.Logs)
	}
}

func TestHandleJobTailNotFound(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/jobs/tail?id=deadbeef", nil)
	rec := httptest.NewRecorder()
	s.handleJobTail(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tail unknown status = %d, want 404", rec.Code)
	}
}

func TestParseNonNegativeInt(t *testing.T) {
	cases := map[string]int{"0": 0, "5": 5, "123": 123}
	for in, want := range cases {
		got, err := parseNonNegativeInt(in)
		if err != nil || got != want {
			t.Fatalf("parseNonNegativeInt(%q) = %d,%v want %d", in, got, err, want)
		}
	}
	if _, err := parseNonNegativeInt("-1"); err == nil {
		t.Fatal("expected error for -1")
	}
	if _, err := parseNonNegativeInt("abc"); err == nil {
		t.Fatal("expected error for abc")
	}
}
