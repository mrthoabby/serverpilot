package users

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// configDir is the base directory for ServerPilot config files.
	configDir = "/etc/serverpilot"
	// registryFile tracks which users were created by ServerPilot.
	registryFile = "/etc/serverpilot/deploy-users.json"
	// deployGroup is the Linux group for all deploy users.
	deployGroup = "deploy"
	// defaultShell restricts deploy users to bash (no login shell = /usr/sbin/nologin
	// would block SSH key-based deploys, so we use bash but with no sudo).
	defaultShell = "/bin/bash"
)

// validUsername allows only lowercase alphanumeric, hyphens, underscores.
// Max 32 chars, must start with a letter.  Prevents injection in shell commands.
var validUsername = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// DeployUser represents a managed deploy user.
type DeployUser struct {
	Username  string    `json:"username"`
	SSHOnly   bool      `json:"ssh_only"`             // true = no password, SSH key auth only
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"` // admin who created it
}

// registry holds the list of users managed by ServerPilot.
type registry struct {
	Users []DeployUser `json:"users"`
}

var mu sync.Mutex

// CreateUser creates a new Linux system user for deployments.
// The user is added to the "deploy" group (created if it doesn't exist),
// with a home directory and the specified password.
func CreateUser(username, password string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: must be 1-32 chars, lowercase alphanumeric/hyphen/underscore, start with a letter")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	mu.Lock()
	defer mu.Unlock()

	// Check if user already exists in the system.
	if userExists(username) {
		return fmt.Errorf("user '%s' already exists", username)
	}

	// Ensure the deploy group exists.
	if err := ensureGroup(deployGroup); err != nil {
		return fmt.Errorf("failed to create deploy group: %w", err)
	}

	// Create the user with home directory, deploy group, and restricted shell.
	// --create-home: creates /home/<username>
	// --gid deploy:  primary group is "deploy"
	// --shell:       login shell
	// --comment:     identifies this as a ServerPilot-managed user
	cmd := exec.Command("/usr/sbin/useradd",
		"--create-home",
		"--gid", deployGroup,
		"--shell", defaultShell,
		"--comment", "ServerPilot deploy user",
		username,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Set the password via chpasswd (reads from stdin: "user:password").
	if err := setPassword(username, password); err != nil {
		// Rollback: remove the user we just created.
		_ = exec.Command("/usr/sbin/userdel", "--remove", username).Run()
		return fmt.Errorf("failed to set password: %w", err)
	}

	// Register in our tracking file.
	reg := loadRegistry()
	reg.Users = append(reg.Users, DeployUser{
		Username:  username,
		CreatedAt: time.Now(),
	})
	if err := saveRegistry(reg); err != nil {
		return fmt.Errorf("user created but failed to save registry: %w", err)
	}

	return nil
}

// ListUsers returns all deploy users managed by ServerPilot.
// It cross-checks the registry against actual system users to stay accurate.
func ListUsers() []DeployUser {
	mu.Lock()
	defer mu.Unlock()

	reg := loadRegistry()
	var alive []DeployUser
	for _, u := range reg.Users {
		if userExists(u.Username) {
			alive = append(alive, u)
		}
	}

	// Update registry if stale entries were removed.
	if len(alive) != len(reg.Users) {
		reg.Users = alive
		_ = saveRegistry(reg)
	}

	return alive
}

// ResetPassword changes the password for an existing deploy user.
func ResetPassword(username, newPassword string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username")
	}
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	mu.Lock()
	defer mu.Unlock()

	// Only allow resetting passwords of users we manage.
	if !isManaged(username) {
		return fmt.Errorf("user '%s' is not a ServerPilot-managed deploy user", username)
	}

	if !userExists(username) {
		return fmt.Errorf("user '%s' does not exist in the system", username)
	}

	return setPassword(username, newPassword)
}

// DeleteUser removes a deploy user from the system and the registry.
func DeleteUser(username string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(username) {
		return fmt.Errorf("user '%s' is not a ServerPilot-managed deploy user", username)
	}

	// Remove the system user and their home directory.
	cmd := exec.Command("/usr/sbin/userdel", "--remove", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("userdel failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Remove from registry.
	reg := loadRegistry()
	var updated []DeployUser
	for _, u := range reg.Users {
		if u.Username != username {
			updated = append(updated, u)
		}
	}
	reg.Users = updated
	_ = saveRegistry(reg)

	return nil
}

// CreateSSHUser creates a Linux user with no password (locked), SSH key auth only.
// The public key is written to /home/<username>/.ssh/authorized_keys with strict
// permissions (0700 .ssh dir, 0600 authorized_keys, owned by the new user).
func CreateSSHUser(username, publicKey string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: must be 1-32 chars, lowercase alphanumeric/hyphen/underscore, start with a letter")
	}
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return fmt.Errorf("SSH public key is required")
	}
	if !isValidSSHPubKey(publicKey) {
		return fmt.Errorf("invalid SSH public key format (expected ssh-rsa, ssh-ed25519, ecdsa-sha2-*, or sk-* key)")
	}

	mu.Lock()
	defer mu.Unlock()

	if userExists(username) {
		return fmt.Errorf("user '%s' already exists", username)
	}

	if err := ensureGroup(deployGroup); err != nil {
		return fmt.Errorf("failed to create deploy group: %w", err)
	}

	// Create the user with home directory, deploy group, and bash shell.
	cmd := exec.Command("/usr/sbin/useradd",
		"--create-home",
		"--gid", deployGroup,
		"--shell", defaultShell,
		"--comment", "ServerPilot deploy user (SSH-only)",
		username,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Lock the password so nobody can log in with a password.
	// passwd -l prepends '!' to the hash in /etc/shadow.
	if out, err := exec.Command("/usr/bin/passwd", "-l", username).CombinedOutput(); err != nil {
		_ = exec.Command("/usr/sbin/userdel", "--remove", username).Run()
		return fmt.Errorf("failed to lock password: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Write the SSH public key.
	if err := writeAuthorizedKeys(username, publicKey); err != nil {
		_ = exec.Command("/usr/sbin/userdel", "--remove", username).Run()
		return fmt.Errorf("failed to set up SSH key: %w", err)
	}

	// Register in tracking file.
	reg := loadRegistry()
	reg.Users = append(reg.Users, DeployUser{
		Username:  username,
		SSHOnly:   true,
		CreatedAt: time.Now(),
	})
	if err := saveRegistry(reg); err != nil {
		return fmt.Errorf("user created but failed to save registry: %w", err)
	}

	return nil
}

// AddSSHKey appends an SSH public key to an existing managed user's authorized_keys.
func AddSSHKey(username, publicKey string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username")
	}
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return fmt.Errorf("SSH public key is required")
	}
	if !isValidSSHPubKey(publicKey) {
		return fmt.Errorf("invalid SSH public key format")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(username) {
		return fmt.Errorf("user '%s' is not a ServerPilot-managed deploy user", username)
	}

	return appendAuthorizedKey(username, publicKey)
}

// GetSSHKeys reads the authorized_keys file for a managed user.
func GetSSHKeys(username string) ([]string, error) {
	if !validUsername.MatchString(username) {
		return nil, fmt.Errorf("invalid username")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(username) {
		return nil, fmt.Errorf("user '%s' is not a ServerPilot-managed deploy user", username)
	}

	homeDir := filepath.Join("/home", username)
	akPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	data, err := os.ReadFile(akPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

// userExists checks if a Linux user exists via /etc/passwd lookup (no shell).
func userExists(username string) bool {
	cmd := exec.Command("/usr/bin/id", "-u", username)
	return cmd.Run() == nil
}

// ensureGroup creates the Linux group if it doesn't exist.
func ensureGroup(name string) error {
	cmd := exec.Command("/usr/bin/getent", "group", name)
	if cmd.Run() == nil {
		return nil // already exists
	}
	out, err := exec.Command("/usr/sbin/groupadd", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// setPassword sets the password for a user using chpasswd.
// The password is passed via stdin pipe, never as a command-line argument
// (which would be visible in /proc and ps output — CWE-214).
func setPassword(username, password string) error {
	cmd := exec.Command("/usr/sbin/chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// writeAuthorizedKeys creates /home/<user>/.ssh/authorized_keys with the given key.
// Sets strict ownership and permissions (required by sshd StrictModes).
func writeAuthorizedKeys(username, pubKey string) error {
	homeDir := filepath.Join("/home", username)
	sshDir := filepath.Join(homeDir, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	// Create .ssh directory with 0700.
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh dir: %w", err)
	}

	// Write authorized_keys with 0600.
	if err := os.WriteFile(akPath, []byte(pubKey+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// chown -R user:deploy /home/user/.ssh
	// Must be owned by the user, otherwise sshd rejects the key.
	cmd := exec.Command("/bin/chown", "-R", username+":"+deployGroup, sshDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// appendAuthorizedKey adds a key to an existing authorized_keys file.
func appendAuthorizedKey(username, pubKey string) error {
	homeDir := filepath.Join("/home", username)
	sshDir := filepath.Join(homeDir, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	// Ensure .ssh exists.
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	// Read existing keys to avoid duplicates.
	existing, _ := os.ReadFile(akPath)
	if strings.Contains(string(existing), pubKey) {
		return fmt.Errorf("key already exists for this user")
	}

	f, err := os.OpenFile(akPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(pubKey + "\n"); err != nil {
		return err
	}

	// Fix ownership.
	cmd := exec.Command("/bin/chown", "-R", username+":"+deployGroup, sshDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// isValidSSHPubKey checks that the key starts with a recognized SSH key type prefix.
// This prevents injecting arbitrary content into authorized_keys.
func isValidSSHPubKey(key string) bool {
	validPrefixes := []string{
		"ssh-rsa ",
		"ssh-ed25519 ",
		"ecdsa-sha2-nistp256 ",
		"ecdsa-sha2-nistp384 ",
		"ecdsa-sha2-nistp521 ",
		"sk-ssh-ed25519@openssh.com ",
		"sk-ecdsa-sha2-nistp256@openssh.com ",
	}
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// isManaged returns true if the username is in the ServerPilot registry.
func isManaged(username string) bool {
	reg := loadRegistry()
	for _, u := range reg.Users {
		if u.Username == username {
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
