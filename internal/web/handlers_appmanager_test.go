package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrthoabby/serverpilot/internal/appmanager"
)

func TestAppManagerPageRejectsUnboundedValues(t *testing.T) {
	for _, target := range []string{"/?limit=201", "/?limit=0", "/?offset=-1", "/?offset=1000001"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if _, _, err := appManagerPage(req); err == nil {
			t.Fatalf("expected invalid pagination for %s", target)
		}
	}
}

func TestAppManagerCreateApplicationUsesStrictJSON(t *testing.T) {
	dir := t.TempDir()
	service, err := appmanager.Open(filepath.Join(dir, "appmanager.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := &Server{appManager: service}
	req := httptest.NewRequest(http.MethodPost, "/api/app-manager/applications/create", strings.NewReader(`{"repository_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unknown":true}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handleAppManagerApplicationCreate(recorder, req)
	if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "unknown") {
		t.Fatalf("strict JSON rejection must be generic, got %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAppManagerMutationRejectsWrongMethod(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.handleAppManagerDeploy(recorder, httptest.NewRequest(http.MethodGet, "/api/app-manager/deployments/create", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected method rejection, got %d", recorder.Code)
	}
}
