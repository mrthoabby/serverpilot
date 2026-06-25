package web

import (
	"crypto/subtle"
	"log"
	"net/http"
	"time"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

type sessionReauthRequest struct {
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type sessionRevokeRequest struct {
	ID string `json:"id"`
}

type mfaEnableRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

func (s *Server) handleSessionReauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	token, ok := s.currentSessionToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	username, ok := s.sessionStore.ValidateSession(token)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
		return
	}
	var req sessionReauthRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if len(req.Password) == 0 || len(req.Password) > 256 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid password"})
		return
	}

	freshConfig, err := auth.LoadConfig()
	if err != nil {
		log.Printf("reauth: failed to reload config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to load credentials"})
		return
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(freshConfig.Username)) == 1
	passwordOK := auth.ValidatePassword(freshConfig, req.Password)
	if !usernameOK || !passwordOK {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid credentials"})
		return
	}
	if freshConfig.MFAEnabled && !auth.ValidateTOTPCode(freshConfig.TOTPSecret, req.MFACode, time.Now()) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid MFA code"})
		return
	}
	s.config = freshConfig
	if !s.sessionStore.MarkReauthenticated(token) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"reauthenticated": true,
		"expires_in_sec":  int(auth.ReauthMaxAge.Seconds()),
	}})
}

func (s *Server) handleSessionReauthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	token, ok := s.currentSessionToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	username, valid := s.sessionStore.ValidateSession(token)
	if !valid {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
		return
	}
	recent := s.sessionStore.RecentlyReauthenticated(token)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"recently_reauthenticated": recent,
		"reauth_max_sec":           int(auth.ReauthMaxAge.Seconds()),
		"username":                 username,
	}})
}

func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	token, ok := s.currentSessionToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    s.sessionStore.ListSessions(token),
	})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req sessionRevokeRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.ID == "" || len(req.ID) > 64 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid session id"})
		return
	}
	revoked := s.sessionStore.RevokeSession(req.ID)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]bool{"revoked": revoked}})
}

func (s *Server) handleSessionRevokeOthers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	token, ok := s.currentSessionToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	count := s.sessionStore.RevokeOtherSessions(token)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]int{"revoked": count}})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to generate MFA secret"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"secret":      secret,
		"otpauth_uri": auth.TOTPAuthURL(s.config.Username, secret),
	}})
}

func (s *Server) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req mfaEnableRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if !auth.ValidateTOTPCode(req.Secret, req.Code, time.Now()) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid MFA code"})
		return
	}
	s.config.MFAEnabled = true
	s.config.TOTPSecret = req.Secret
	if err := auth.SaveConfig(*s.config); err != nil {
		log.Printf("mfa/enable: save config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save MFA settings"})
		return
	}
	token, _ := s.currentSessionToken(r)
	revoked := s.sessionStore.RevokeOtherSessions(token)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"mfa_enabled": true,
		"revoked":     revoked,
	}})
}

func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	s.config.MFAEnabled = false
	s.config.TOTPSecret = ""
	if err := auth.SaveConfig(*s.config); err != nil {
		log.Printf("mfa/disable: save config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save MFA settings"})
		return
	}
	token, _ := s.currentSessionToken(r)
	revoked := s.sessionStore.RevokeOtherSessions(token)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"mfa_enabled": false,
		"revoked":     revoked,
	}})
}
