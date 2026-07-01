package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

func TestNormalizeLoginEmail(t *testing.T) {
	got, ok := normalizeLoginEmail(" ADMIN@Example.COM ")
	if !ok || got != "admin@example.com" {
		t.Fatalf("normalize = %q, %v", got, ok)
	}
	if _, ok := normalizeLoginEmail("bad<script>@example.com"); ok {
		t.Fatal("HTML email should be rejected")
	}
}

func TestEmailOTPManagerVerifyConsumesAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	m := newEmailOTPManager()
	m.now = func() time.Time { return now }
	m.save("admin@example.com", emailOTPLoginPurpose, "secret", "123456")
	if !m.verify("admin@example.com", emailOTPLoginPurpose, "secret", "123456") {
		t.Fatal("expected valid code")
	}
	if m.verify("admin@example.com", emailOTPLoginPurpose, "secret", "123456") {
		t.Fatal("code must be one-time use")
	}

	m.save("admin@example.com", emailOTPLoginPurpose, "secret", "999999")
	now = now.Add(emailOTPTTL + time.Second)
	if m.verify("admin@example.com", emailOTPLoginPurpose, "secret", "999999") {
		t.Fatal("expired code must fail")
	}
}

func TestEmailOTPManagerMaxAttempts(t *testing.T) {
	m := newEmailOTPManager()
	m.save("admin@example.com", emailOTPLoginPurpose, "secret", "123456")
	for i := 0; i < emailOTPMaxAttempts; i++ {
		if m.verify("admin@example.com", emailOTPLoginPurpose, "secret", "000000") {
			t.Fatal("wrong code should fail")
		}
	}
	if m.verify("admin@example.com", emailOTPLoginPurpose, "secret", "123456") {
		t.Fatal("code should be deleted after max attempts")
	}
}

func TestEmailLoginRequestCodeSendsEmailSenderPayload(t *testing.T) {
	var gotAuth string
	var gotPayload emailDeliveryPayload
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	cfg := testEmailLoginConfig(upstream.URL)
	restore := stubEmailLoginConfig(cfg)
	defer restore()

	s := &Server{config: cfg, sessionStore: auth.NewSessionStore(), emailOTP: newEmailOTPManager()}
	req := httptest.NewRequest(http.MethodPost, "/api/login/email/request-code", strings.NewReader(`{"email":"admin@example.com"}`))
	rec := httptest.NewRecorder()

	s.handleEmailLoginRequestCode(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotAuth != "Bearer machine-token" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotPayload.To != "admin@example.com" || gotPayload.Scope != "auth" || gotPayload.Template != "serverpilot_login_code" {
		t.Fatalf("payload = %#v", gotPayload)
	}
	if gotPayload.Data["code"] == "" || gotPayload.Data["expires_minutes"] != "10" {
		t.Fatalf("payload data = %#v", gotPayload.Data)
	}
}

func TestEmailLoginRequestCodeIsOpaqueForUnauthorizedEmail(t *testing.T) {
	sent := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	cfg := testEmailLoginConfig(upstream.URL)
	restore := stubEmailLoginConfig(cfg)
	defer restore()

	s := &Server{config: cfg, sessionStore: auth.NewSessionStore(), emailOTP: newEmailOTPManager()}
	req := httptest.NewRequest(http.MethodPost, "/api/login/email/request-code", strings.NewReader(`{"email":"other@example.com"}`))
	rec := httptest.NewRecorder()

	s.handleEmailLoginRequestCode(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if sent != 0 {
		t.Fatalf("unauthorized email sent %d deliveries", sent)
	}
}

func TestEmailLoginVerifyCodeCreatesSessionCookie(t *testing.T) {
	cfg := testEmailLoginConfig("https://email.example.test/api/internal/deliveries")
	restore := stubEmailLoginConfig(cfg)
	defer restore()

	s := &Server{config: cfg, sessionStore: auth.NewSessionStore(), emailOTP: newEmailOTPManager()}
	s.emailOTP.save("admin@example.com", emailOTPLoginPurpose, cfg.SessionSecret, "123456")
	req := httptest.NewRequest(http.MethodPost, "/api/login/email/verify-code", strings.NewReader(`{"email":"admin@example.com","code":"123456"}`))
	rec := httptest.NewRecorder()

	s.handleEmailLoginVerifyCode(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if cookie := rec.Result().Cookies(); len(cookie) == 0 {
		t.Fatal("expected session cookie")
	}
}

func TestSettingsGetDoesNotReturnEmailDeliveryToken(t *testing.T) {
	s := &Server{config: testEmailLoginConfig("https://email.example.test/api/internal/deliveries"), sessionStore: auth.NewSessionStore()}
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec := httptest.NewRecorder()

	s.handleSettingsGet(rec, req)

	if strings.Contains(rec.Body.String(), "machine-token") {
		t.Fatalf("settings response leaked token: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"email_delivery_token_configured":true`) {
		t.Fatalf("settings response missing token flag: %s", rec.Body.String())
	}
}

func TestSettingsEmailLoginPreservesAndUpdatesToken(t *testing.T) {
	cfg := testEmailLoginConfig("https://old.example.test/api/internal/deliveries")
	var saved auth.Config
	restore := stubEmailLoginSave(func(in auth.Config) error {
		saved = in
		return nil
	})
	defer restore()

	s := &Server{config: cfg, sessionStore: auth.NewSessionStore()}
	body := `{"enabled":true,"email":"admin@example.com","url":"https://new.example.test/api/internal/deliveries","token":"","scope":"auth","template":"serverpilot_login_code","timeout_sec":5}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/email-login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.handleSettingsEmailLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if saved.EmailDeliveryAuthToken != "machine-token" {
		t.Fatalf("token was not preserved: %q", saved.EmailDeliveryAuthToken)
	}

	body = `{"enabled":true,"email":"admin@example.com","url":"https://new.example.test/api/internal/deliveries","token":"new-token","scope":"auth","template":"serverpilot_login_code","timeout_sec":5}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings/email-login", strings.NewReader(body))
	rec = httptest.NewRecorder()
	s.handleSettingsEmailLogin(rec, req)
	if saved.EmailDeliveryAuthToken != "new-token" {
		t.Fatalf("token was not updated: %q", saved.EmailDeliveryAuthToken)
	}
}

func testEmailLoginConfig(url string) *auth.Config {
	return &auth.Config{
		Username:                "admin",
		SessionSecret:           "test-session-secret",
		EmailLoginEnabled:       true,
		EmailLoginAddress:       "admin@example.com",
		EmailDeliveryURL:        url,
		EmailDeliveryAuthToken:  "machine-token",
		EmailDeliveryScope:      "auth",
		EmailDeliveryTemplate:   "serverpilot_login_code",
		EmailDeliveryTimeoutSec: 5,
	}
}

func stubEmailLoginConfig(cfg *auth.Config) func() {
	old := emailLoginLoadConfig
	emailLoginLoadConfig = func() (*auth.Config, error) { return cfg, nil }
	return func() { emailLoginLoadConfig = old }
}

func stubEmailLoginSave(fn func(auth.Config) error) func() {
	old := emailLoginSaveConfig
	emailLoginSaveConfig = fn
	return func() { emailLoginSaveConfig = old }
}
