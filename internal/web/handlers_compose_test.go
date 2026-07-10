package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrthoabby/serverpilot/internal/compose"
)

func TestComposeHandlersRejectWrongMethod(t *testing.T) {
	cleanup := compose.SetRegistryRootForTests(t.TempDir())
	defer cleanup()

	s := &Server{}
	cases := []struct {
		name   string
		h      http.HandlerFunc
		method string
	}{
		{"list", s.handleComposeProjectsList, http.MethodPost},
		{"validate", s.handleComposeValidate, http.MethodGet},
		{"deploy", s.handleComposeDeploy, http.MethodGet},
		{"clone", s.handleComposeClone, http.MethodGet},
		{"sync", s.handleComposeSync, http.MethodGet},
		{"delete", s.handleComposeDelete, http.MethodGet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/compose/"+tc.name, nil)
			rec := httptest.NewRecorder()
			tc.h(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d", rec.Code)
			}
		})
	}
}

func TestComposeValidateRejectsUnknownFields(t *testing.T) {
	cleanup := compose.SetRegistryRootForTests(t.TempDir())
	defer cleanup()

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/compose/validate", strings.NewReader(`{"name":"shop","root_dir":"/opt/shop","compose_file":"docker-compose.yml","extra":true}`))
	rec := httptest.NewRecorder()
	s.handleComposeValidate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDependenciesListGET(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/dependencies", nil)
	rec := httptest.NewRecorder()
	s.handleDependenciesList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"docker"`) {
		t.Fatalf("expected docker in response: %s", rec.Body.String())
	}
}

func TestDependenciesListRejectsPOST(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/dependencies", nil)
	rec := httptest.NewRecorder()
	s.handleDependenciesList(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
