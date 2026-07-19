package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHandleContainerDeleteRejectsWrongMethod(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/containers/delete", nil)
	rec := httptest.NewRecorder()
	s.handleContainerDelete(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleContainerDeleteRequiresContainer(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/containers/delete", strings.NewReader(`{"remove_image":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleContainerDelete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
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
