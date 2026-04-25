package auth

import (
	"bufio"
	"crypto/rand"
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
	Username        string `json:"username"`
	PasswordHash    string `json:"password_hash"`
	SessionSecret   string `json:"session_secret"`
	Domain          string `json:"domain,omitempty"`
	Email           string `json:"email,omitempty"`
	SSLEnabled      bool   `json:"ssl_enabled,omitempty"`
	InsecureBlocked bool   `json:"insecure_blocked,omitempty"`
}

// sessionEntry holds a session token with its creation time for TTL expiration.
type sessionEntry struct {
	username  string
	createdAt time.Time
}

// sessionMaxAge is the server-side session lifetime. Matches the cookie MaxAge.
const sessionMaxAge = 24 * time.Hour

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

// cleanupLoop removes expired sessions periodically to prevent unbounded
// map growth from abandoned sessions.
func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, entry := range s.sessions {
			if now.Sub(entry.createdAt) > sessionMaxAge {
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
func ResetPassword(config *Config, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	config.PasswordHash = string(hash)
	return saveConfig(*config)
}

// GenerateSessionToken creates a cryptographically secure random token.
func GenerateSessionToken() (string, error) {
	return generateRandomHex(32)
}

// AddSession stores a session token in the session store with a creation timestamp.
func (s *SessionStore) AddSession(token, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionEntry{username: username, createdAt: time.Now()}
}

// ValidateSession checks if a session token is valid and not expired.
func (s *SessionStore) ValidateSession(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[token]
	if !ok {
		return "", false
	}
	// Reject expired sessions even before the cleanup loop runs.
	if time.Since(entry.createdAt) > sessionMaxAge {
		return "", false
	}
	return entry.username, true
}

// RemoveSession removes a session token from the store.
func (s *SessionStore) RemoveSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// SaveConfig persists the configuration to disk. Exported for use by settings handlers.
func SaveConfig(config Config) error {
	return saveConfig(config)
}

func saveConfig(config Config) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
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
