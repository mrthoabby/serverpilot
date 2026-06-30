package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

func TestSessionStatusUnauthenticatedDoesNotReturn401(t *testing.T) {
	s := &Server{config: &auth.Config{}, sessionStore: auth.NewSessionStore()}
	req := httptest.NewRequest(http.MethodGet, "/api/session/status", nil)
	rec := httptest.NewRecorder()

	s.handleSessionStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data type = %T, want object", resp.Data)
	}
	if data["authenticated"] != false {
		t.Fatalf("authenticated = %v, want false", data["authenticated"])
	}
}

func TestSessionStatusAuthenticated(t *testing.T) {
	s := &Server{config: &auth.Config{}, sessionStore: auth.NewSessionStore()}
	const token = "valid-session-token"
	s.sessionStore.AddSession(token, "admin", "127.0.0.1", "test")

	req := httptest.NewRequest(http.MethodGet, "/api/session/status", nil)
	req.AddCookie(&http.Cookie{Name: legacySessionCookieName, Value: token})
	rec := httptest.NewRecorder()

	s.handleSessionStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data type = %T, want object", resp.Data)
	}
	if data["authenticated"] != true {
		t.Fatalf("authenticated = %v, want true", data["authenticated"])
	}
	if data["username"] != "admin" {
		t.Fatalf("username = %v, want admin", data["username"])
	}
}

func TestSessionStatusRejectsWrongMethod(t *testing.T) {
	s := &Server{config: &auth.Config{}, sessionStore: auth.NewSessionStore()}
	req := httptest.NewRequest(http.MethodPost, "/api/session/status", nil)
	rec := httptest.NewRecorder()

	s.handleSessionStatus(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
