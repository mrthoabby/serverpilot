package users

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	// Imported = true means the user pre-existed in /etc/passwd and was
	// only registered by ServerPilot (NOT created by it). Delete on an
	// imported user is non-destructive: removes from the dashboard
	// registry and from the `deploy` group, but leaves the OS user
	// intact. Created-by-dashboard users get a destructive userdel.
	Imported bool `json:"imported,omitempty"`
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

// DeleteUser removes a deploy user from the system and the registry. The
// destructiveness depends on how the user was first registered:
//
//   - If the user was CREATED by the dashboard (Imported = false), this
//     runs `userdel --remove` to remove the OS user and their home dir.
//   - If the user was IMPORTED (Imported = true), this only revokes
//     dashboard ownership: removes from the registry and from the
//     `deploy` group, but leaves the /etc/passwd entry, the home dir,
//     and any non-deploy group memberships untouched. That respects the
//     principle that the dashboard should never destroy state it didn't
//     create.
func DeleteUser(username string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	mu.Lock()
	defer mu.Unlock()

	imported := false
	for _, u := range loadRegistry().Users {
		if u.Username == username {
			imported = u.Imported
			break
		}
	}
	if !isManaged(username) {
		return fmt.Errorf("user '%s' is not a ServerPilot-managed deploy user", username)
	}

	if imported {
		// Non-destructive path: remove from `deploy` group, leave OS user
		// alone. Idempotent — gpasswd exits non-zero if not a member,
		// which we treat as success.
		cmd := exec.Command(findUserBinary("gpasswd"), "-d", username, "--", deployGroup)
		_ = cmd.Run() // ignore error; user may not have been in the group
	} else {
		// Destructive path: userdel + remove home dir.
		cmd := exec.Command("/usr/sbin/userdel", "--remove", username)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("userdel failed: %s (%w)", strings.TrimSpace(string(out)), err)
		}
	}

	// Remove from registry in both cases.
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

// ImportExistingUser registers an OS-level user with the dashboard and
// adds them to the `deploy` group. The user MUST already exist in
// /etc/passwd. This is the "I created a user manually with useradd, now
// I want the dashboard to manage it too" path.
//
// Defences applied:
//   - Strict regex validation on the username — never lets a value with
//     shell metacharacters or a leading "-" reach gpasswd.
//   - Existence check via getent (NSS-aware) before any state change.
//   - Refuses to import a user that's already managed (idempotency
//     would mask attempted state corruption).
//   - Idempotent gpasswd -a (already in deploy → no-op exit 0).
//   - Atomic registry write via the existing saveRegistry path.
func ImportExistingUser(username string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: must be 1-32 chars, lowercase alphanumeric/hyphen/underscore, start with a letter")
	}

	mu.Lock()
	defer mu.Unlock()

	if isManaged(username) {
		return fmt.Errorf("user '%s' is already managed by ServerPilot", username)
	}
	if !userExists(username) {
		return fmt.Errorf("user '%s' does not exist in /etc/passwd — create it first or use the Generate keypair / Password tab", username)
	}

	// Make sure the deploy group exists. Idempotent.
	if err := ensureGroup(deployGroup); err != nil {
		return fmt.Errorf("failed to ensure deploy group: %w", err)
	}

	// Add to deploy group. gpasswd -a is idempotent (notice on dup, exit 0).
	// Note the arg order: USER comes before "--", which itself comes before
	// the group. Putting "--" between "-a" and USER would make gpasswd
	// consume "--" as the username (exit code 3).
	gpasswd := findUserBinary("gpasswd")
	if gpasswd == "" {
		return fmt.Errorf("gpasswd not available — cannot manage groups")
	}
	cmd := exec.Command(gpasswd, "-a", username, "--", deployGroup)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpasswd add failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// Detect ssh_only by checking if the user has authorized_keys but no
	// usable password (passwd -l locked or shadow has '!' / '*'). This is
	// best-effort metadata for the UI badge — never used to make a security
	// decision. Default to "ssh_only=false" if we can't tell.
	sshOnly := userPasswordLocked(username)

	reg := loadRegistry()
	reg.Users = append(reg.Users, DeployUser{
		Username:  username,
		SSHOnly:   sshOnly,
		CreatedAt: time.Now(),
		Imported:  true,
	})
	if err := saveRegistry(reg); err != nil {
		// Try to roll back the group add so the registry stays in sync.
		_ = exec.Command(gpasswd, "-d", username, "--", deployGroup).Run()
		return fmt.Errorf("user added to group but registry write failed: %w", err)
	}

	return nil
}

// SystemUser is a non-system OS user (UID ≥ 1000) with the metadata the
// dashboard's user-explorer needs.
type SystemUser struct {
	Username string   `json:"username"`
	UID      int      `json:"uid"`
	Groups   []string `json:"groups"`           // every group the user belongs to (informational)
	Shell    string   `json:"shell,omitempty"`
	Managed  bool     `json:"managed"`          // true iff the user is in /etc/serverpilot/deploy-users.json
	SSHOnly  bool     `json:"ssh_only,omitempty"`
}

// ListSystemUsers enumerates the non-system users on the host and the
// groups each one belongs to, plus a flag indicating whether they are in
// the dashboard's managed-users registry. Used by the System Users panel.
//
// Defences applied:
//   - Reads /etc/passwd directly (no NSS shell-out) so a misconfigured
//     LDAP / sssd cannot stall the dashboard.
//   - Skips entries where the username does not match validUsername —
//     guarantees the value is safe to flow into log lines and JSON.
//   - Filters UID < 1000 (system daemons) and UID == 65534 (`nobody`)
//     so the operator only sees real human / service-deploy users.
func ListSystemUsers() ([]SystemUser, error) {
	mu.Lock()
	defer mu.Unlock()

	managedSet := map[string]bool{}
	managedSSHOnly := map[string]bool{}
	for _, u := range loadRegistry().Users {
		managedSet[u.Username] = true
		managedSSHOnly[u.Username] = u.SSHOnly
	}

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("cannot read /etc/passwd")
	}
	defer f.Close()

	groupIndex := buildGroupIndex() // map[username] -> []groupNames

	var out []SystemUser
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Format: username:x:uid:gid:gecos:home:shell
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		if !validUsername.MatchString(username) {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		if uid < 1000 || uid == 65534 {
			continue
		}
		groups := groupIndex[username]
		// Sort the group list so the UI rendering is stable.
		sort.Strings(groups)
		out = append(out, SystemUser{
			Username: username,
			UID:      uid,
			Groups:   groups,
			Shell:    parts[6],
			Managed:  managedSet[username],
			SSHOnly:  managedSSHOnly[username],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// buildGroupIndex scans /etc/group and returns a map of username → group
// names. Reads the file directly (no NSS) for the same robustness reason
// as ListSystemUsers.
func buildGroupIndex() map[string][]string {
	idx := map[string][]string{}
	f, err := os.Open("/etc/group")
	if err != nil {
		return idx
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Format: groupname:x:gid:user1,user2,...
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) < 4 {
			continue
		}
		group := parts[0]
		for _, member := range strings.Split(parts[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			idx[member] = append(idx[member], group)
		}
	}
	return idx
}

// allowedManageableGroups is the closed set of groups the dashboard will
// add/remove via the System Users panel. Mirrors (a subset of) the
// allowlist in internal/permissions/groups.go but is duplicated here to
// keep this package free of an import cycle. Adding a group here is a
// security decision — group membership = capability grant.
var allowedManageableGroups = map[string]struct {
	Description string
	Dangerous   bool
}{
	"deploy": {Description: "ServerPilot deploy group (port allocation, /opt access)", Dangerous: false},
	"docker": {Description: "Run docker without sudo (effectively root)", Dangerous: true},
}

// AllowedManageableGroups returns the catalog the UI uses to render the
// per-user toggles.
func AllowedManageableGroups() map[string]struct {
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
} {
	out := make(map[string]struct {
		Description string `json:"description"`
		Dangerous   bool   `json:"dangerous"`
	})
	for k, v := range allowedManageableGroups {
		out[k] = struct {
			Description string `json:"description"`
			Dangerous   bool   `json:"dangerous"`
		}{Description: v.Description, Dangerous: v.Dangerous}
	}
	return out
}

// SetGroupMembership adds (`true`) or removes (`false`) `username` from
// `group`. Validates against the allowlist; refuses anything outside.
// Idempotent — gpasswd notices a no-op and exits 0.
func SetGroupMembership(username, group string, add bool) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username")
	}
	if _, ok := allowedManageableGroups[group]; !ok {
		return fmt.Errorf("group %q is not manageable from the dashboard", group)
	}

	mu.Lock()
	defer mu.Unlock()

	if !userExists(username) {
		return fmt.Errorf("user '%s' does not exist", username)
	}
	if err := ensureGroup(group); err != nil {
		return fmt.Errorf("failed to ensure group: %w", err)
	}

	gpasswd := findUserBinary("gpasswd")
	if gpasswd == "" {
		return fmt.Errorf("gpasswd not available")
	}

	var cmd *exec.Cmd
	if add {
		// `--` between USER and GROUP — putting it before USER would make
		// gpasswd consume `--` as the username and exit 3.
		cmd = exec.Command(gpasswd, "-a", username, "--", group)
	} else {
		cmd = exec.Command(gpasswd, "-d", username, "--", group)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// gpasswd -d on a non-member exits non-zero; treat as success.
		if !add && strings.Contains(strings.ToLower(string(out)), "is not a member") {
			return nil
		}
		return fmt.Errorf("gpasswd failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// userPasswordLocked returns true if the user's account has a locked
// password (`passwd -l` style). Reads /etc/shadow which requires root;
// returns false on any error so the UI defaults to "Password" badge,
// which is the safe assumption (no false claim of SSH-only).
func userPasswordLocked(username string) bool {
	out, err := exec.Command("/usr/bin/passwd", "-S", username).Output()
	if err != nil {
		return false
	}
	// `passwd -S` format: "<user> <status> <date> <min> <max> <warn> <inactive>"
	// where status is L (locked), P (usable), NP (no password).
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return false
	}
	return fields[1] == "L"
}

// findUserBinary mirrors the binpaths logic in internal/permissions, but
// kept local to avoid an import cycle. Picks the first existing absolute
// path among well-known locations.
func findUserBinary(name string) string {
	candidates := map[string][]string{
		"gpasswd": {"/usr/bin/gpasswd", "/usr/sbin/gpasswd", "/sbin/gpasswd", "/bin/gpasswd"},
	}
	for _, p := range candidates[name] {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
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
