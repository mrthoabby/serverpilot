package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const configDir = "/etc/serverpilot"
const configFile = "/etc/serverpilot/config.json"

// Config holds the authentication and ServerPilot configuration.
type Config struct {
	Username                string `json:"username"`
	PasswordHash            string `json:"password_hash"`
	SessionSecret           string `json:"session_secret"`
	Domain                  string `json:"domain,omitempty"`
	Email                   string `json:"email,omitempty"`
	SSLEnabled              bool   `json:"ssl_enabled,omitempty"`
	InsecureBlocked         bool   `json:"insecure_blocked,omitempty"`
	MFAEnabled              bool   `json:"mfa_enabled,omitempty"`
	TOTPSecret              string `json:"totp_secret,omitempty"`
	EmailLoginEnabled       bool   `json:"email_login_enabled,omitempty"`
	EmailLoginAddress       string `json:"email_login_address,omitempty"`
	EmailDeliveryURL        string `json:"email_delivery_url,omitempty"`
	EmailDeliveryAuthToken  string `json:"email_delivery_auth_token,omitempty"`
	EmailDeliveryScope      string `json:"email_delivery_scope,omitempty"`
	EmailDeliveryTemplate   string `json:"email_delivery_template,omitempty"`
	EmailDeliveryTimeoutSec int    `json:"email_delivery_timeout_sec,omitempty"`
	PreviousVersion         string `json:"previous_version,omitempty"`
}

// sessionEntry holds a session token with its creation time for TTL expiration.
type sessionEntry struct {
	id                string
	username          string
	createdAt         time.Time
	lastSeenAt        time.Time
	reauthenticatedAt time.Time
	ip                string
	userAgent         string
}

const (
	// SessionMaxAge is the absolute server-side session lifetime.
	SessionMaxAge = 12 * time.Hour
	// SessionIdleTimeout expires sessions that have not made a request recently.
	SessionIdleTimeout = 30 * time.Minute
	// ReauthMaxAge is how long password/MFA reauthentication is valid for
	// sensitive operations.
	ReauthMaxAge = 15 * time.Minute
)

// SessionInfo is the redacted session view returned to the dashboard.
type SessionInfo struct {
	ID                    string    `json:"id"`
	Username              string    `json:"username"`
	CreatedAt             time.Time `json:"created_at"`
	LastSeenAt            time.Time `json:"last_seen_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	IdleExpiresAt         time.Time `json:"idle_expires_at"`
	ReauthenticatedAt     time.Time `json:"reauthenticated_at"`
	ReauthenticationUntil time.Time `json:"reauthentication_until"`
	IP                    string    `json:"ip"`
	UserAgent             string    `json:"user_agent"`
	Current               bool      `json:"current"`
}

// SessionStore manages active sessions in memory with automatic TTL cleanup.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry // token -> entry
}

// NewSessionStore creates a new in-memory session store and starts a
// background goroutine that purges expired sessions every hour.
func NewSessionStore() *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]sessionEntry),
	}
	go s.cleanupLoop()
	return s
}

// cleanupLoop removes expired sessions periodically to prevent unbounded map
// growth from abandoned sessions.
func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, entry := range s.sessions {
			if sessionExpired(entry, now) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// SetupCredentials prompts the user for a username and password,
// hashes the password with bcrypt, generates a session secret,
// and saves the configuration to disk.
func SetupCredentials() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter admin username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	fmt.Print("Enter admin password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	secret, err := generateRandomHex(32)
	if err != nil {
		return fmt.Errorf("failed to generate session secret: %w", err)
	}

	config := Config{
		Username:      username,
		PasswordHash:  string(hash),
		SessionSecret: secret,
	}

	if err := saveConfig(config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Admin user '%s' created successfully.\n", username)
	return nil
}

// LoadConfig reads the configuration from disk.
func LoadConfig() (*Config, error) {
	absPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	// Validate the path is within the expected directory.
	if !strings.HasPrefix(absPath, configDir) {
		return nil, fmt.Errorf("config path outside expected directory")
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// ValidatePassword checks a plaintext password against the stored bcrypt hash.
func ValidatePassword(config *Config, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(password))
	return err == nil
}

// ResetPassword updates the password hash for an existing config and saves it.
//
// Hardening (CWE-521 — weak password policy): the previous version only
// required 8 characters. We now also require a minimum length of 12 and at
// least three character classes. We additionally reject the username as the
// password, and reject a small block-list of trivially common passwords.
func ResetPassword(config *Config, newPassword string) error {
	if err := validatePasswordStrength(config.Username, newPassword); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	config.PasswordHash = string(hash)
	return saveConfig(*config)
}

// validatePasswordStrength enforces a baseline policy. It is intentionally
// modest — for an internet-exposed admin dashboard, also enable the per-IP
// login lockout (see internal/web/middleware.go) and ideally a 2FA layer.
func validatePasswordStrength(username, pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(pw) > 256 {
		return fmt.Errorf("password too long")
	}
	if username != "" && strings.EqualFold(pw, username) {
		return fmt.Errorf("password cannot equal the username")
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 33 && r <= 126:
			hasSymbol = true
		}
	}
	classes := 0
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if b {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("password must include at least three of: lowercase, uppercase, digits, symbols")
	}
	// A tiny, illustrative blocklist. Operators should integrate a HIBP-style
	// breach-list check in a future iteration.
	common := map[string]bool{
		"password":      true,
		"password123":   true,
		"admin":         true,
		"administrator": true,
		"changeme":      true,
		"letmein":       true,
		"qwerty123456":  true,
	}
	if common[strings.ToLower(pw)] {
		return fmt.Errorf("password is too common")
	}
	return nil
}

// GenerateSessionToken creates a cryptographically secure random token.
func GenerateSessionToken() (string, error) {
	return generateRandomHex(32)
}

// AddSession stores a session token in the session store with metadata for
// inventory, idle expiration, and recent-reauth checks.
func (s *SessionStore) AddSession(token, username, ip, userAgent string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sessions[token] = sessionEntry{
		id:                sessionID(token),
		username:          username,
		createdAt:         now,
		lastSeenAt:        now,
		reauthenticatedAt: now,
		ip:                sanitizeSessionField(ip, 64),
		userAgent:         sanitizeSessionField(userAgent, 200),
	}
}

// ValidateSession checks if a session token is valid and not expired.
func (s *SessionStore) ValidateSession(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[token]
	if !ok {
		return "", false
	}
	// Reject expired sessions even before the cleanup loop runs.
	now := time.Now()
	if sessionExpired(entry, now) {
		delete(s.sessions, token)
		return "", false
	}
	entry.lastSeenAt = now
	s.sessions[token] = entry
	return entry.username, true
}

// MarkReauthenticated records that the current session recently completed a
// password/MFA challenge.
func (s *SessionStore) MarkReauthenticated(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[token]
	if !ok || sessionExpired(entry, time.Now()) {
		if ok {
			delete(s.sessions, token)
		}
		return false
	}
	entry.reauthenticatedAt = time.Now()
	entry.lastSeenAt = entry.reauthenticatedAt
	s.sessions[token] = entry
	return true
}

// RecentlyReauthenticated returns true when the session completed a password
// or MFA challenge inside ReauthMaxAge.
func (s *SessionStore) RecentlyReauthenticated(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[token]
	if !ok {
		return false
	}
	now := time.Now()
	if sessionExpired(entry, now) {
		return false
	}
	return !entry.reauthenticatedAt.IsZero() && now.Sub(entry.reauthenticatedAt) <= ReauthMaxAge
}

// RemoveSession removes a session token from the store.
func (s *SessionStore) RemoveSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// ListSessions returns all live sessions, redacted for API output.
func (s *SessionStore) ListSessions(currentToken string) []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []SessionInfo
	for token, entry := range s.sessions {
		if sessionExpired(entry, now) {
			delete(s.sessions, token)
			continue
		}
		out = append(out, entry.info(token == currentToken))
	}
	return out
}

// RevokeSession removes one session by redacted session id. The current
// session can be revoked intentionally by passing its id.
func (s *SessionStore) RevokeSession(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, entry := range s.sessions {
		if entry.id == id {
			delete(s.sessions, token)
			return true
		}
	}
	return false
}

// RevokeOtherSessions removes every live session except the caller's token.
func (s *SessionStore) RevokeOtherSessions(currentToken string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token := range s.sessions {
		if token == currentToken {
			continue
		}
		delete(s.sessions, token)
		count++
	}
	return count
}

func sessionExpired(entry sessionEntry, now time.Time) bool {
	return now.Sub(entry.createdAt) > SessionMaxAge || now.Sub(entry.lastSeenAt) > SessionIdleTimeout
}

func (entry sessionEntry) info(current bool) SessionInfo {
	return SessionInfo{
		ID:                    entry.id,
		Username:              entry.username,
		CreatedAt:             entry.createdAt,
		LastSeenAt:            entry.lastSeenAt,
		ExpiresAt:             entry.createdAt.Add(SessionMaxAge),
		IdleExpiresAt:         entry.lastSeenAt.Add(SessionIdleTimeout),
		ReauthenticatedAt:     entry.reauthenticatedAt,
		ReauthenticationUntil: entry.reauthenticatedAt.Add(ReauthMaxAge),
		IP:                    entry.ip,
		UserAgent:             entry.userAgent,
		Current:               current,
	}
}

func sessionID(token string) string {
	sum := sha256Hex(token)
	if len(sum) > 24 {
		return sum[:24]
	}
	return sum
}

func sanitizeSessionField(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > maxLen {
		return out[:maxLen]
	}
	return out
}

func sha256Hex(s string) string {
	// Isolated helper to avoid exporting token hashes. The full session token
	// is never exposed; only a short hash prefix is used as a revocation id.
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// SaveConfig persists the configuration to disk. Exported for use by settings handlers.
func SaveConfig(config Config) error {
	return saveConfig(config)
}

func saveConfig(config Config) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Atomic write: create the temp file in the SAME directory so the rename
	// is on the same filesystem (and thus genuinely atomic). Use os.CreateTemp
	// to avoid a predictable temp filename that an attacker could pre-create.
	tmp, err := os.CreateTemp(configDir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp config file")
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod temp config")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp config")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync temp config")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp config")
	}
	if err := os.Rename(tmpPath, configFile); err != nil {
		return fmt.Errorf("failed to install config file")
	}
	return nil
}

func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
