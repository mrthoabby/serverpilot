// Package dbquery implements a small, secure database query runner for the
// ServerPilot dashboard. It lets the operator save a connection (DSN +
// engine + label), then issue ad-hoc SQL queries against it with bounded
// time/result, audit-logged on every call.
//
// Security model:
//
//   - Connection metadata (DSN incl. password) is encrypted at rest with
//     AES-256-GCM. The encryption key is derived from the dashboard's
//     `session_secret` via HKDF-SHA256 with the "sp-db-vault-v1" context,
//     so a backup of the vault file alone cannot recover credentials —
//     the master secret material lives in /etc/serverpilot/config.json.
//
//   - Connections are opened just-in-time per query and closed afterwards.
//     No persistent pool. This makes credential rotation trivial (next
//     query reads the latest from the vault) and avoids stale-connection
//     surprises after long idle periods.
//
//   - Every query runs with a context-bound 30s timeout and capped row +
//     byte limits. Runaway queries return early with a clear error rather
//     than tying up the dashboard.
//
//   - Engine allowlist: postgres and mysql/mariadb. Anything else is
//     rejected at the SDK boundary so the driver registry can never be
//     tricked into loading an unexpected protocol.
//
//   - Errors returned to the API are sanitized — driver errors that
//     contain credentials, host names, or paths get replaced by generic
//     phrases. The full error goes to journald only.
//
//   - Audit log records actor, connection_id, query SHA-256 (NOT the
//     query text — queries can contain secrets in literals), duration,
//     row count, success/error.
package dbquery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	vaultFile        = "/etc/serverpilot/db-vault.json"
	hkdfContextLabel = "sp-db-vault-v1"
	minSecretLen     = 32

	// QueryTimeout caps how long a single query may run before its
	// context is canceled. 30s is generous for a dashboard tool — the
	// operator gets feedback fast on runaway selects.
	QueryTimeout = 30 * time.Second

	// MaxResultRows caps the number of rows returned per query.
	MaxResultRows = 1000

	// MaxResultBytes caps total bytes serialized into the JSON response.
	// Defends against `SELECT * FROM huge_blob_table` blowing up memory.
	MaxResultBytes = 10 * 1024 * 1024 // 10 MB
)

// Engine enumerates the supported database engines. Closed set; anything
// not in this list is refused at the SDK boundary.
type Engine string

const (
	EnginePostgres Engine = "postgres"
	EngineMySQL    Engine = "mysql"
)

// EngineDriver returns the driver name registered with database/sql.
// Imported in dbquery_drivers.go via blank import.
func (e Engine) DriverName() string {
	switch e {
	case EnginePostgres:
		return "postgres"
	case EngineMySQL:
		return "mysql"
	}
	return ""
}

// Valid returns true if e is one of the allowlisted engines.
func (e Engine) Valid() bool {
	return e == EnginePostgres || e == EngineMySQL
}

// Connection is the on-disk shape of a saved DB connection. The DSN is
// encrypted (Nonce + Ciphertext); other fields are plaintext metadata
// the operator typed when saving. Fields are stable; never rename.
type Connection struct {
	ID          string `json:"id"`           // dashboard-generated, opaque
	Name        string `json:"name"`         // operator-friendly label
	Engine      Engine `json:"engine"`
	Algorithm   string `json:"alg"`          // "AES-256-GCM"
	Nonce       string `json:"nonce"`        // base64
	Ciphertext  string `json:"ciphertext"`   // base64 (encrypted DSN)
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// PublicConnection is what the API returns when listing — same as
// Connection but WITHOUT the encrypted material so a misuse of the list
// endpoint cannot leak ciphertext.
type PublicConnection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Engine      Engine `json:"engine"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// vault is the on-disk file shape.
type vault struct {
	Connections []Connection `json:"connections"`
}

// Service is the public façade. All package state changes go through it.
type Service struct {
	mu sync.Mutex
}

// NewService returns a Service ready to use. There is no per-instance
// state beyond the lock; the vault file is the source of truth.
func NewService() *Service { return &Service{} }

// nameRegex restricts the operator-supplied connection name to a
// conservative set so the value can be logged + displayed without
// escape ambiguity. Disallows control characters, newlines, and HTML
// brackets — defends against XSS via the connection list view.
var nameRegex = regexp.MustCompile(`^[A-Za-z0-9 ._@+-]{1,64}$`)

// ── Public API ────────────────────────────────────────────────────────

// SaveConnectionInput is the payload an operator sends to create or
// update a connection. The DSN is plaintext at this hop (HTTPS protects
// it in transit); we encrypt before persisting.
type SaveConnectionInput struct {
	ID          string `json:"id"` // empty = create new
	Name        string `json:"name"`
	Engine      Engine `json:"engine"`
	DSN         string `json:"dsn"`
	Description string `json:"description"`
}

// SaveConnection encrypts the DSN and writes the connection to the
// vault. Returns the public view of the saved record.
func (s *Service) SaveConnection(in SaveConnectionInput, sessionSecret string) (PublicConnection, error) {
	if !in.Engine.Valid() {
		return PublicConnection{}, fmt.Errorf("unsupported engine %q", in.Engine)
	}
	if !nameRegex.MatchString(in.Name) {
		return PublicConnection{}, errors.New("invalid name (allowed: A-Z a-z 0-9 space . _ @ + -, max 64)")
	}
	if in.DSN == "" {
		return PublicConnection{}, errors.New("dsn is required")
	}
	if len(in.DSN) > 4096 {
		return PublicConnection{}, errors.New("dsn too long")
	}
	if len(sessionSecret) < minSecretLen {
		return PublicConnection{}, errors.New("vault unavailable")
	}

	dsn, err := normalizeDSN(in.Engine, in.DSN)
	if err != nil {
		return PublicConnection{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := loadVault()
	if err != nil {
		return PublicConnection{}, fmt.Errorf("vault load failed")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	entry, err := encryptConn(in, dsn, sessionSecret, now)
	if err != nil {
		return PublicConnection{}, fmt.Errorf("encryption failed")
	}

	if entry.ID == "" {
		entry.ID = generateID()
	}

	replaced := false
	for i, c := range v.Connections {
		if c.ID == entry.ID {
			entry.CreatedAt = c.CreatedAt
			v.Connections[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		entry.CreatedAt = now
		v.Connections = append(v.Connections, entry)
	}

	if err := saveVault(v); err != nil {
		return PublicConnection{}, fmt.Errorf("vault write failed")
	}
	return entry.publicView(), nil
}

// ListConnections returns the public view (no ciphertext) of every saved
// connection. Cheap; called every time the dashboard renders the list.
func (s *Service) ListConnections() ([]PublicConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := loadVault()
	if err != nil {
		return nil, fmt.Errorf("vault load failed")
	}
	out := make([]PublicConnection, 0, len(v.Connections))
	for _, c := range v.Connections {
		out = append(out, c.publicView())
	}
	return out, nil
}

// DeleteConnection removes a connection from the vault. Idempotent.
func (s *Service) DeleteConnection(id string) error {
	if id == "" {
		return errors.New("id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := loadVault()
	if err != nil {
		return fmt.Errorf("vault load failed")
	}
	out := make([]Connection, 0, len(v.Connections))
	for _, c := range v.Connections {
		if c.ID != id {
			out = append(out, c)
		}
	}
	v.Connections = out
	return saveVault(v)
}

// resolveDSN finds the connection by id and decrypts its DSN. Used by
// TestConnection and ExecuteQuery. Internal — callers MUST pass the
// session secret from the dashboard config.
func (s *Service) resolveDSN(id, sessionSecret string) (Engine, string, *Connection, error) {
	if id == "" {
		return "", "", nil, errors.New("connection id required")
	}
	if len(sessionSecret) < minSecretLen {
		return "", "", nil, errors.New("vault unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := loadVault()
	if err != nil {
		return "", "", nil, fmt.Errorf("vault load failed")
	}
	for i := range v.Connections {
		if v.Connections[i].ID == id {
			dsn, err := decryptConn(v.Connections[i], sessionSecret)
			if err != nil {
				return "", "", nil, fmt.Errorf("decryption failed")
			}
			return v.Connections[i].Engine, dsn, &v.Connections[i], nil
		}
	}
	return "", "", nil, errors.New("connection not found")
}

// ── Crypto + persistence ─────────────────────────────────────────────

func deriveVaultKey(secret string) ([]byte, error) {
	if len(secret) < minSecretLen {
		return nil, errors.New("session secret too short")
	}
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(hkdfContextLabel))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptConn(in SaveConnectionInput, dsn, secret, now string) (Connection, error) {
	key, err := deriveVaultKey(secret)
	if err != nil {
		return Connection{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Connection{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Connection{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Connection{}, err
	}
	ct := gcm.Seal(nil, nonce, []byte(dsn), nil)
	return Connection{
		ID:          in.ID,
		Name:        in.Name,
		Engine:      in.Engine,
		Description: in.Description,
		Algorithm:   "AES-256-GCM",
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:  base64.StdEncoding.EncodeToString(ct),
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func decryptConn(c Connection, secret string) (string, error) {
	if c.Algorithm != "AES-256-GCM" {
		return "", errors.New("unsupported algorithm")
	}
	key, err := deriveVaultKey(secret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(c.Nonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(c.Ciphertext)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", errors.New("decrypt failed")
	}
	return string(plain), nil
}

func loadVault() (*vault, error) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &vault{}, nil
		}
		return nil, err
	}
	var v vault
	if err := json.Unmarshal(data, &v); err != nil {
		return &vault{}, nil
	}
	return &v, nil
}

func saveVault(v *vault) error {
	if err := os.MkdirAll("/etc/serverpilot", 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("/etc/serverpilot", ".db-vault-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, vaultFile)
}

// generateID returns a 64-bit hex id. Cryptographically random because
// the IDs are used in URLs (no enumeration tease) and as map keys in
// the in-memory store.
func generateID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Extremely unlikely; fall back to a timestamp-derived id so we
		// never fail the API call for this.
		return fmt.Sprintf("ts-%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (c Connection) publicView() PublicConnection {
	return PublicConnection{
		ID:          c.ID,
		Name:        c.Name,
		Engine:      c.Engine,
		Description: c.Description,
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
	}
}
