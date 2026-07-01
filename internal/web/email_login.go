package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

const (
	emailOTPLoginPurpose  = "login"
	emailOTPReauthPurpose = "reauth"

	emailOTPCodeDigits       = 6
	emailOTPTTL              = 10 * time.Minute
	emailOTPMaxAttempts      = 5
	emailOTPRateWindow       = 10 * time.Minute
	emailOTPMaxRequests      = 5
	emailOTPMaxVerifications = 10

	defaultEmailDeliveryScope      = "auth"
	defaultEmailDeliveryTemplate   = "serverpilot_login_code"
	defaultEmailDeliveryTimeoutSec = 5
	maxEmailDeliveryTimeoutSec     = 30

	emailLoginGenericMessage = "If email login is configured, a code will be sent."
)

var (
	emailLoginLoadConfig = auth.LoadConfig
	emailLoginSaveConfig = auth.SaveConfig
)

type emailOTPEntry struct {
	Email     string
	Purpose   string
	CodeHash  string
	ExpiresAt time.Time
	Attempts  int
}

type emailOTPRateState struct {
	Count     int
	FirstSeen time.Time
}

type emailOTPManager struct {
	mu         sync.Mutex
	codes      map[string]emailOTPEntry
	rateLimits map[string]emailOTPRateState
	now        func() time.Time
}

func newEmailOTPManager() *emailOTPManager {
	return &emailOTPManager{
		codes:      make(map[string]emailOTPEntry),
		rateLimits: make(map[string]emailOTPRateState),
		now:        time.Now,
	}
}

func (s *Server) emailOTPManager() *emailOTPManager {
	if s.emailOTP == nil {
		s.emailOTP = newEmailOTPManager()
	}
	return s.emailOTP
}

func (m *emailOTPManager) requestAllowed(kind, ip, email, purpose string, max int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	key := strings.Join([]string{kind, ip, email, purpose}, "|")
	st := m.rateLimits[key]
	if st.FirstSeen.IsZero() || now.Sub(st.FirstSeen) > emailOTPRateWindow {
		m.rateLimits[key] = emailOTPRateState{Count: 1, FirstSeen: now}
		return true
	}
	if st.Count >= max {
		return false
	}
	st.Count++
	m.rateLimits[key] = st
	return true
}

func (m *emailOTPManager) save(email, purpose, secret, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[emailOTPKey(email, purpose)] = emailOTPEntry{
		Email:     email,
		Purpose:   purpose,
		CodeHash:  emailOTPCodeHash(secret, email, purpose, code),
		ExpiresAt: m.now().Add(emailOTPTTL),
	}
}

func (m *emailOTPManager) verify(email, purpose, secret, code string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := emailOTPKey(email, purpose)
	entry, ok := m.codes[key]
	if !ok {
		return false
	}
	if m.now().After(entry.ExpiresAt) {
		delete(m.codes, key)
		return false
	}
	entry.Attempts++
	if entry.Attempts > emailOTPMaxAttempts {
		delete(m.codes, key)
		return false
	}
	expected := []byte(entry.CodeHash)
	got := []byte(emailOTPCodeHash(secret, email, purpose, code))
	if hmac.Equal(expected, got) {
		delete(m.codes, key)
		return true
	}
	m.codes[key] = entry
	return false
}

func emailOTPKey(email, purpose string) string {
	return purpose + "|" + email
}

func emailOTPCodeHash(secret, email, purpose, code string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(email))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateEmailOTPCode() (string, error) {
	var b strings.Builder
	b.Grow(emailOTPCodeDigits)
	for i := 0; i < emailOTPCodeDigits; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}
	return b.String(), nil
}

func normalizeLoginEmail(raw string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 254 || containsHTML(email) {
		return "", false
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return "", false
	}
	return email, true
}

func redactedEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return "invalid-email"
	}
	return email[:1] + "***" + email[at:]
}

type emailDeliveryConfig struct {
	URL        string
	Token      string
	Scope      string
	Template   string
	TimeoutSec int
}

func emailDeliveryConfigFromAuthConfig(cfg *auth.Config) emailDeliveryConfig {
	scope := strings.TrimSpace(cfg.EmailDeliveryScope)
	if scope == "" {
		scope = defaultEmailDeliveryScope
	}
	template := strings.TrimSpace(cfg.EmailDeliveryTemplate)
	if template == "" {
		template = defaultEmailDeliveryTemplate
	}
	timeout := cfg.EmailDeliveryTimeoutSec
	if timeout <= 0 {
		timeout = defaultEmailDeliveryTimeoutSec
	}
	return emailDeliveryConfig{
		URL:        strings.TrimSpace(cfg.EmailDeliveryURL),
		Token:      strings.TrimSpace(cfg.EmailDeliveryAuthToken),
		Scope:      scope,
		Template:   template,
		TimeoutSec: timeout,
	}
}

func (c emailDeliveryConfig) configured() bool {
	return c.URL != "" && c.Token != "" && c.Scope != "" && c.Template != ""
}

type emailDeliveryPayload struct {
	To       string            `json:"to"`
	Scope    string            `json:"scope"`
	Template string            `json:"template"`
	Data     map[string]string `json:"data"`
}

func sendEmailOTP(ctx context.Context, cfg emailDeliveryConfig, to, code, domain string) error {
	if !cfg.configured() {
		return fmt.Errorf("email delivery is not configured")
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > maxEmailDeliveryTimeoutSec*time.Second {
		timeout = defaultEmailDeliveryTimeoutSec * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload := emailDeliveryPayload{
		To:       to,
		Scope:    cfg.Scope,
		Template: cfg.Template,
		Data: map[string]string{
			"code":            code,
			"email":           to,
			"domain":          domain,
			"expires_minutes": fmt.Sprintf("%d", int(emailOTPTTL.Minutes())),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("email delivery marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("email delivery request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("email delivery unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg := readEmailDeliveryError(resp.Body)
		return fmt.Errorf("email delivery rejected status=%d detail=%s", resp.StatusCode, sanitizeLogField(msg, 500))
	}
	return nil
}

func readEmailDeliveryError(r io.Reader) string {
	if r == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(r, 2048))
	if err != nil {
		return "failed to read upstream response"
	}
	return strings.TrimSpace(string(data))
}

type emailLoginRequest struct {
	Email string `json:"email"`
}

type emailLoginVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (s *Server) handleLoginOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	cfg := s.config
	if fresh, err := emailLoginLoadConfig(); err == nil {
		cfg = fresh
		s.config = fresh
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"email_login_enabled": cfg.EmailLoginEnabled,
	}})
}

func (s *Server) handleEmailLoginRequestCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req emailLoginRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": emailLoginGenericMessage}})
		return
	}
	s.requestEmailOTP(r, req.Email, emailOTPLoginPurpose)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": emailLoginGenericMessage}})
}

func (s *Server) handleEmailLoginVerifyCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	clientIP := extractClientIP(r)
	if allowed, retryAfter := loginAttemptCheck(clientIP); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, apiResponse{Error: "too many failed attempts; try again later"})
		return
	}
	var req emailLoginVerifyRequest
	if err := jsonDecode(r, &req); err != nil {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	email, ok := normalizeLoginEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if !ok || len(code) != emailOTPCodeDigits || !allDigits(code) {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	cfg := s.freshConfigForEmailLogin()
	if !emailLoginConfigAllows(cfg, email) || !s.emailOTPManager().requestAllowed("verify", clientIP, email, emailOTPLoginPurpose, emailOTPMaxVerifications) {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	if !s.emailOTPManager().verify(email, emailOTPLoginPurpose, cfg.SessionSecret, code) {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	loginAttemptRecord(clientIP, true)
	if err := s.startAuthenticatedSession(w, r, cfg.Username); err != nil {
		log.Printf("email login: session create failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "logged in"}})
}

func (s *Server) handleSessionReauthEmailRequestCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	if _, ok := s.currentSessionToken(r); !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	cfg := s.freshConfigForEmailLogin()
	s.requestEmailOTP(r, cfg.EmailLoginAddress, emailOTPReauthPurpose)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": emailLoginGenericMessage}})
}

func (s *Server) handleSessionReauthEmailVerifyCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	token, ok := s.currentSessionToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
		return
	}
	if _, ok := s.sessionStore.ValidateSession(token); !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	cfg := s.freshConfigForEmailLogin()
	email := strings.ToLower(strings.TrimSpace(cfg.EmailLoginAddress))
	code := strings.TrimSpace(req.Code)
	clientIP := extractClientIP(r)
	if !emailLoginConfigAllows(cfg, email) ||
		len(code) != emailOTPCodeDigits ||
		!allDigits(code) ||
		!s.emailOTPManager().requestAllowed("verify", clientIP, email, emailOTPReauthPurpose, emailOTPMaxVerifications) ||
		!s.emailOTPManager().verify(email, emailOTPReauthPurpose, cfg.SessionSecret, code) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid code"})
		return
	}
	if !s.sessionStore.MarkReauthenticated(token) {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"reauthenticated": true,
		"expires_in_sec":  int(auth.ReauthMaxAge.Seconds()),
	}})
}

func (s *Server) requestEmailOTP(r *http.Request, rawEmail, purpose string) {
	clientIP := extractClientIP(r)
	email, ok := normalizeLoginEmail(rawEmail)
	if !ok {
		return
	}
	if !s.emailOTPManager().requestAllowed("request", clientIP, email, purpose, emailOTPMaxRequests) {
		log.Printf("email login: rate limited request ip=%s email=%s purpose=%s", sanitizeLogField(clientIP, 45), redactedEmail(email), purpose)
		return
	}
	cfg := s.freshConfigForEmailLogin()
	if !emailLoginConfigAllows(cfg, email) {
		return
	}
	code, err := generateEmailOTPCode()
	if err != nil {
		log.Printf("email login: code generation failed: %v", err)
		return
	}
	if err := sendEmailOTP(r.Context(), emailDeliveryConfigFromAuthConfig(cfg), email, code, cfg.Domain); err != nil {
		log.Printf("email login: delivery failed email=%s purpose=%s error=%s", redactedEmail(email), purpose, sanitizeLogField(err.Error(), 500))
		return
	}
	s.emailOTPManager().save(email, purpose, cfg.SessionSecret, code)
	log.Printf("email login: code sent email=%s purpose=%s", redactedEmail(email), purpose)
}

func (s *Server) freshConfigForEmailLogin() *auth.Config {
	cfg, err := emailLoginLoadConfig()
	if err != nil {
		log.Printf("email login: failed to reload config: %v", err)
		return s.config
	}
	s.config = cfg
	return cfg
}

func emailLoginConfigAllows(cfg *auth.Config, email string) bool {
	if cfg == nil || !cfg.EmailLoginEnabled {
		return false
	}
	configured, ok := normalizeLoginEmail(cfg.EmailLoginAddress)
	if !ok || configured != email {
		return false
	}
	return emailDeliveryConfigFromAuthConfig(cfg).configured()
}

func (s *Server) startAuthenticatedSession(w http.ResponseWriter, r *http.Request, username string) error {
	token, err := auth.GenerateSessionToken()
	if err != nil {
		return err
	}
	s.sessionStore.AddSession(token, username, extractClientIP(r), r.Header.Get("User-Agent"))
	s.sessionStore.MarkReauthenticated(token)
	s.setSessionCookie(w, token)
	return nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func validateEmailDeliverySettings(cfg emailDeliveryConfig, enabled bool, loginEmail string) error {
	if _, ok := normalizeLoginEmail(loginEmail); enabled && !ok {
		return fmt.Errorf("invalid login email")
	}
	if cfg.Scope == "" {
		cfg.Scope = defaultEmailDeliveryScope
	}
	if cfg.Template == "" {
		cfg.Template = defaultEmailDeliveryTemplate
	}
	if enabled {
		if cfg.URL == "" {
			return fmt.Errorf("email delivery URL is required")
		}
		if _, err := url.ParseRequestURI(cfg.URL); err != nil {
			return fmt.Errorf("invalid email delivery URL")
		}
		if cfg.Token == "" {
			return fmt.Errorf("email delivery token is required")
		}
	}
	if cfg.URL != "" {
		parsed, err := url.ParseRequestURI(cfg.URL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return fmt.Errorf("invalid email delivery URL")
		}
	}
	if !simpleIdentifier(cfg.Scope, 64) || !simpleIdentifier(cfg.Template, 96) {
		return fmt.Errorf("invalid email delivery scope or template")
	}
	if cfg.TimeoutSec <= 0 || cfg.TimeoutSec > maxEmailDeliveryTimeoutSec {
		return fmt.Errorf("invalid email delivery timeout")
	}
	return nil
}

func simpleIdentifier(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
