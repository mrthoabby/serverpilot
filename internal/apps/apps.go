package apps

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// appsBaseDir is where managed application directories live.
	appsBaseDir = "/opt"
	// configDir for the registry file.
	configDir = "/etc/serverpilot"
	// registryFile tracks which apps were created by ServerPilot.
	registryFile = "/etc/serverpilot/managed-apps.json"
	// maxEnvFileSize caps .env files at 64 KB to prevent abuse.
	maxEnvFileSize = 64 * 1024
)

// validAppName: lowercase alphanumeric, hyphens, underscores.
// Must start with a letter. Max 64 chars. Prevents path injection.
var validAppName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// validEnvFileName: optional prefix (alphanumeric/hyphens/underscores), always ends with .env
// Examples: ".env", "procs.env", "staging.env", "my-app.env"
// The regex matches both ".env" (no prefix) and "prefix.env" forms.
var validEnvFileName = regexp.MustCompile(`^\.env$|^[a-z0-9][a-z0-9_-]*\.env$`)

// ManagedApp represents an application directory managed by ServerPilot.
type ManagedApp struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	EnvFiles  []string  `json:"env_files,omitempty"` // populated on list
}

// EnvFileContent holds the content of an .env file, encrypted for transport.
type EnvFileContent struct {
	App      string `json:"app"`
	FileName string `json:"file_name"`
	// Content is AES-256-GCM encrypted, then base64-encoded for JSON transport.
	// The frontend must send the encrypted blob back for saving.
	Content       string `json:"content"`
	Encrypted     bool   `json:"encrypted"`
	SizeBytes     int    `json:"size_bytes"`
	LastModified  string `json:"last_modified,omitempty"`
}

// registry holds the list of managed apps.
type registry struct {
	Apps []ManagedApp `json:"apps"`
}

var mu sync.Mutex

// ── Encryption key management ────────────────────────────────────────────
//
// A per-boot ephemeral key protects .env content in transit between the Go
// server and the browser.  The key lives only in memory — it is never written
// to disk, so even if the browser's JS is inspected, the ciphertext is
// useless without this process's memory.
//
// On every server restart a new key is generated, which means any cached
// encrypted blobs from a previous session are automatically invalidated.

var (
	transportKey   []byte
	transportKeyMu sync.Mutex
)

// getTransportKey returns the per-process AES-256 transport key, generating
// it lazily on first use. Lazy generation lets the process start even if the
// kernel CSPRNG is briefly unavailable at boot — the previous version called
// init() and panicked on rand.Reader failure, which converted a transient
// /dev/urandom hiccup into a hard daemon crash and a denial-of-service for
// every other endpoint that did not need crypto.
func getTransportKey() ([]byte, error) {
	transportKeyMu.Lock()
	defer transportKeyMu.Unlock()
	if transportKey != nil {
		return transportKey, nil
	}
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("CSPRNG unavailable")
	}
	transportKey = k
	return transportKey, nil
}

// encryptContent encrypts plaintext with AES-256-GCM and returns a
// base64-encoded string (nonce || ciphertext).
func encryptContent(plaintext []byte) (string, error) {
	key, err := getTransportKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptContent reverses encryptContent.
func decryptContent(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	key, err := getTransportKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (key may have rotated after restart): %w", err)
	}
	return plaintext, nil
}

// ── App CRUD ─────────────────────────────────────────────────────────────

// CreateApp creates a new application directory in /opt/<name>.
// It also creates a default .env file inside.
func CreateApp(name string) error {
	if !validAppName.MatchString(name) {
		return fmt.Errorf("invalid app name: must be 1-64 chars, lowercase alphanumeric/hyphen/underscore, start with a letter")
	}

	mu.Lock()
	defer mu.Unlock()

	appPath := filepath.Join(appsBaseDir, name)

	// Verify the resolved path is still under /opt (defence against symlink tricks).
	absPath, err := filepath.Abs(appPath)
	if err != nil || !strings.HasPrefix(absPath, appsBaseDir+"/") {
		return fmt.Errorf("path traversal detected")
	}

	// Check if directory already exists.
	if _, err := os.Stat(absPath); err == nil {
		return fmt.Errorf("directory /opt/%s already exists", name)
	}

	// Create the directory with 0755 (readable by deploy users).
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create a default .env file with mode 0660. The owner is root (the
	// daemon) and the group is whatever the parent dir's group is (root
	// unless the dir has setgid). The 0660 mode is critical when the
	// parent directory has a POSIX default ACL: the kernel uses the mode's
	// GROUP bits as the ACL mask. Mode 0600 sets mask to ---, which would
	// silently neutralise every named ACL entry inherited from the dir
	// (e.g., the deploy user grant). Mode 0660 leaves mask=rw so named
	// grants from the default ACL actually take effect.
	// We do NOT widen access via traditional UNIX perms — without an ACL,
	// only root (owner) and root group can rw, which is the same as 0600.
	envPath := filepath.Join(absPath, ".env")
	if err := os.WriteFile(envPath, []byte("# Environment variables for "+name+"\n"), 0o660); err != nil {
		// Rollback: remove the directory.
		_ = os.RemoveAll(absPath)
		return fmt.Errorf("failed to create default .env: %w", err)
	}

	// Register in tracking.
	reg := loadRegistry()
	reg.Apps = append(reg.Apps, ManagedApp{
		Name:      name,
		Path:      absPath,
		CreatedAt: time.Now(),
	})
	if err := saveRegistry(reg); err != nil {
		return fmt.Errorf("app created but failed to save registry: %w", err)
	}

	return nil
}

// ListApps returns all managed applications with their .env files.
func ListApps() []ManagedApp {
	mu.Lock()
	defer mu.Unlock()

	reg := loadRegistry()
	var alive []ManagedApp

	for _, app := range reg.Apps {
		// Verify directory still exists.
		if info, err := os.Stat(app.Path); err == nil && info.IsDir() {
			app.EnvFiles = listEnvFilesInDir(app.Path)
			alive = append(alive, app)
		}
	}

	// Prune stale entries.
	if len(alive) != len(reg.Apps) {
		reg.Apps = alive
		_ = saveRegistry(reg)
	}

	return alive
}

// DeleteApp removes the application directory and its registry entry.
func DeleteApp(name string) error {
	if !validAppName.MatchString(name) {
		return fmt.Errorf("invalid app name")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(name) {
		return fmt.Errorf("app '%s' is not a ServerPilot-managed application", name)
	}

	appPath := filepath.Join(appsBaseDir, name)
	absPath, err := filepath.Abs(appPath)
	if err != nil || !strings.HasPrefix(absPath, appsBaseDir+"/") {
		return fmt.Errorf("path traversal detected")
	}

	// Remove directory and all contents.
	if err := os.RemoveAll(absPath); err != nil {
		return fmt.Errorf("failed to remove directory: %w", err)
	}

	// Remove from registry.
	reg := loadRegistry()
	var updated []ManagedApp
	for _, a := range reg.Apps {
		if a.Name != name {
			updated = append(updated, a)
		}
	}
	reg.Apps = updated
	_ = saveRegistry(reg)

	return nil
}

// ── Env file operations ──────────────────────────────────────────────────

// CreateEnvFile creates a new .env file inside a managed app directory.
// If prefix is empty, creates ".env". Otherwise creates "<prefix>.env".
func CreateEnvFile(appName, prefix string) (string, error) {
	if !validAppName.MatchString(appName) {
		return "", fmt.Errorf("invalid app name")
	}

	// Build the filename.
	var fileName string
	if prefix == "" {
		fileName = ".env"
	} else {
		fileName = prefix + ".env"
	}

	if !validEnvFileName.MatchString(fileName) {
		return "", fmt.Errorf("invalid env file name: must be alphanumeric/hyphens/underscores followed by .env")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return "", fmt.Errorf("app '%s' is not a ServerPilot-managed application", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return "", err
	}

	// Check if already exists.
	if _, err := os.Stat(filePath); err == nil {
		return "", fmt.Errorf("file '%s' already exists in %s", fileName, appName)
	}

	// Mode 0660 (see CreateApp comment) so the dir's default ACL mask
	// stays at rw and named ACL grants from filesystem permissions
	// actually work. 0600 would zero the ACL mask and silently lock out
	// every deploy user the operator granted access to.
	header := "# " + fileName + " for " + appName + "\n"
	if err := os.WriteFile(filePath, []byte(header), 0o660); err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}

	return fileName, nil
}

// ReadEnvFile reads and encrypts the content of an .env file for secure transport.
func ReadEnvFile(appName, fileName string) (*EnvFileContent, error) {
	if !validAppName.MatchString(appName) {
		return nil, fmt.Errorf("invalid app name")
	}
	if !validEnvFileName.MatchString(fileName) {
		return nil, fmt.Errorf("invalid file name")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return nil, fmt.Errorf("app '%s' is not managed", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}

	if info.Size() > maxEnvFileSize {
		return nil, fmt.Errorf("file exceeds maximum size of 64 KB")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Encrypt content for transport.
	encrypted, err := encryptContent(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	return &EnvFileContent{
		App:          appName,
		FileName:     fileName,
		Content:      encrypted,
		Encrypted:    true,
		SizeBytes:    len(data),
		LastModified: info.ModTime().Format(time.RFC3339),
	}, nil
}

// ReadEnvFilePlaintext reads an .env file and returns the content as-is.
// SECURITY: This must only be served over authenticated + HTTPS connections.
// The caller (handler) is responsible for enforcing this.
func ReadEnvFilePlaintext(appName, fileName string) (*EnvFileContent, error) {
	if !validAppName.MatchString(appName) {
		return nil, fmt.Errorf("invalid app name")
	}
	if !validEnvFileName.MatchString(fileName) {
		return nil, fmt.Errorf("invalid file name")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return nil, fmt.Errorf("app '%s' is not managed", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}

	if info.Size() > maxEnvFileSize {
		return nil, fmt.Errorf("file exceeds maximum size of 64 KB")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return &EnvFileContent{
		App:          appName,
		FileName:     fileName,
		Content:      string(data),
		Encrypted:    false,
		SizeBytes:    len(data),
		LastModified: info.ModTime().Format(time.RFC3339),
	}, nil
}

// SaveEnvFilePlaintext saves plaintext content to an .env file.
// SECURITY: The content is received as plaintext over the HTTPS + auth channel.
func SaveEnvFilePlaintext(appName, fileName, content string) error {
	if !validAppName.MatchString(appName) {
		return fmt.Errorf("invalid app name")
	}
	if !validEnvFileName.MatchString(fileName) {
		return fmt.Errorf("invalid file name")
	}

	if len(content) > maxEnvFileSize {
		return fmt.Errorf("content exceeds maximum size of 64 KB")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return fmt.Errorf("app '%s' is not managed", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return err
	}

	// Atomic write: temp file then rename.
	// Mode 0660 — see CreateApp comment. With default ACL on the parent
	// dir, this keeps the ACL mask at rw so named grants take effect.
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0o660); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// SaveEnvFile decrypts and saves content to an .env file.
func SaveEnvFile(appName, fileName, encryptedContent string) error {
	if !validAppName.MatchString(appName) {
		return fmt.Errorf("invalid app name")
	}
	if !validEnvFileName.MatchString(fileName) {
		return fmt.Errorf("invalid file name")
	}

	// Decrypt the content from the frontend.
	plaintext, err := decryptContent(encryptedContent)
	if err != nil {
		return fmt.Errorf("failed to decrypt content: %w", err)
	}

	if len(plaintext) > maxEnvFileSize {
		return fmt.Errorf("content exceeds maximum size of 64 KB")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return fmt.Errorf("app '%s' is not managed", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return err
	}

	// Atomic write: write to temp file, then rename.
	// Mode 0660 — see CreateApp comment for the ACL-mask reasoning.
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, plaintext, 0o660); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// DeleteEnvFile removes an .env file from a managed app directory.
func DeleteEnvFile(appName, fileName string) error {
	if !validAppName.MatchString(appName) {
		return fmt.Errorf("invalid app name")
	}
	if !validEnvFileName.MatchString(fileName) {
		return fmt.Errorf("invalid file name")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return fmt.Errorf("app '%s' is not managed", appName)
	}

	filePath, err := safeEnvPath(appName, fileName)
	if err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file '%s' does not exist", fileName)
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

// safeEnvPath builds and validates the full path to an .env file,
// preventing path traversal attacks.
func safeEnvPath(appName, fileName string) (string, error) {
	appDir := filepath.Join(appsBaseDir, appName)
	filePath := filepath.Join(appDir, fileName)

	// Resolve to absolute and verify it's under the app directory.
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	absApp, err := filepath.Abs(appDir)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}

	if !strings.HasPrefix(absFile, absApp+"/") {
		return "", fmt.Errorf("path traversal detected")
	}

	// The file must be directly inside the app dir (no subdirectories).
	if filepath.Dir(absFile) != absApp {
		return "", fmt.Errorf("files must be in the app root directory")
	}

	return absFile, nil
}

// listEnvFilesInDir returns all .env files in a directory.
func listEnvFilesInDir(dirPath string) []string {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil
	}

	var envFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".env") {
			envFiles = append(envFiles, name)
		}
	}
	return envFiles
}

// isManaged returns true if the app name is in the registry.
func isManaged(name string) bool {
	reg := loadRegistry()
	for _, a := range reg.Apps {
		if a.Name == name {
			return true
		}
	}
	return false
}

// ── Registry persistence ─────────────────────────────────────────────────

func loadRegistry() *registry {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		return &registry{}
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return &registry{}
	}
	return &reg
}

func saveRegistry(reg *registry) error {
	absPath, err := filepath.Abs(registryFile)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(absPath, configDir) {
		return fmt.Errorf("registry path outside config directory")
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(absPath, data, 0600)
}
