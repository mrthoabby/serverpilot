package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleContainerReleaseRejectsWrongMethod(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/containers/release", nil)
	rec := httptest.NewRecorder()
	s.handleContainerRelease(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleContainerPortAnalysisRejectsMethod(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPut, "/api/containers/port-analysis?container_id=abc", nil)
	rec := httptest.NewRecorder()
	s.handleContainerPortAnalysis(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleContainerPortAnalysisRequiresContainerID(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/containers/port-analysis", nil)
	rec := httptest.NewRecorder()
	s.handleContainerPortAnalysis(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
