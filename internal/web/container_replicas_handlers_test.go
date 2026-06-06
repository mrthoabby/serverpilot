package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContainerReplicaHandlersRejectWrongMethod(t *testing.T) {
	s := &Server{}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"list", s.handleContainerReplicasList, http.MethodPost},
		{"preview", s.handleContainerReplicaPreview, http.MethodGet},
		{"create", s.handleContainerReplicaCreate, http.MethodGet},
		{"sync", s.handleContainerReplicaSync, http.MethodGet},
		{"delete", s.handleContainerReplicaDelete, http.MethodGet},
		{"update", s.handleContainerReplicaUpdate, http.MethodGet},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/container-replicas", nil)
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestContainerReplicaPreviewRejectsStrictJSON(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/container-replicas/preview", strings.NewReader(`{"parent_id":"abc","extra":true}`))
	rec := httptest.NewRecorder()
	s.handleContainerReplicaPreview(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "invalid request body") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
