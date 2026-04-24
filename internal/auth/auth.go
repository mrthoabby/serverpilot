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

	"golang.org/x/crypto/bcrypt"
)

const configDir = "/etc/serverpilot"
const configFile = "/etc/serverpilot/config.json"

// Config holds the authentication configuration.
type Config struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`
	SessionSecret string `json:"session_secret"`
}

// SessionStore manages active sessions in memory.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]string // token -> username
}

// NewSessionStore creates a new in-memory session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]string),
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

// GenerateSessionToken creates a cryptographically secure random token.
func GenerateSessionToken() (string, error) {
	return generateRandomHex(32)
}

// AddSession stores a session token in the session store.
func (s *SessionStore) AddSession(token, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = username
}

// ValidateSession checks if a session token is valid and returns the username.
func (s *SessionStore) ValidateSession(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	username, ok := s.sessions[token]
	return username, ok
}

// RemoveSession removes a session token from the store.
func (s *SessionStore) RemoveSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
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
