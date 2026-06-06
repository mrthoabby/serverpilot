package portalloc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// Default port range for allocation.
const (
	DefaultMinPort = 3000
	DefaultMaxPort = 3999
)

// lockTTL is how long a reserved port stays locked before it can be
// re-allocated. One minute gives the caller plenty of time to actually
// bind the port after receiving it.
const lockTTL = 1 * time.Minute

const (
	detectedOwnerPrefix       = "detected:"
	detectedDockerOwnerPrefix = "detected:docker:"
	detectedNginxOwnerPrefix  = "detected:nginx:"
)

var (
	proxyPortRegex  = regexp.MustCompile(`\bproxy_pass\s+[^;]*:(\d+)(?:/|;|\s|$)`)
	dailySyncOnce   sync.Once
	dailySyncStopCh = make(chan struct{})
)

// ── Hardening: registry location ─────────────────────────────────────────
//
// Originally the registry lived in /tmp, which is a world-writable directory.
// Combined with the daemon running as root, /tmp is a textbook setup for
// symlink-based privilege escalation: an unprivileged local user could
// pre-create a symlink at /tmp/serverpilot-ports.json (or .lock) pointing
// at /etc/passwd / /etc/shadow / any sensitive root-owned file, and the
// next OpenFile or os.Rename call from ServerPilot would follow the
// symlink as root.
//
// The fix:
//   1. Move the registry into /var/lib/serverpilot/ (root-owned and,
//      once the deploy group exists, group-writable by deploy users only).
//      Other non-root users cannot create or replace entries inside this
//      directory.
//   2. Use O_NOFOLLOW on the lock file (see flock.go) so even if a symlink
//      somehow appears at the lock path, the open fails closed.
//   3. Replace WriteFile + Rename with a CreateTemp-in-same-dir + Rename
//      pattern to keep atomicity but eliminate the predictable temp filename
//      that the old `<path>.tmp` design exposed.
//
// ─────────────────────────────────────────────────────────────────────────

const (
	baseDir      = "/var/lib/serverpilot"
	registryName = "ports.json"
	lockName     = "ports.json.lock"
	accessWX     = 0o3 // POSIX W_OK|X_OK
)

func registryPath() string { return filepath.Join(baseDir, registryName) }
func lockPath() string     { return filepath.Join(baseDir, lockName) }

// deployGroupName matches the constant in internal/users — duplicated here
// to avoid an import cycle (users imports portalloc indirectly via cmd).
const deployGroupName = "deploy"

// ensureBaseDir guarantees that /var/lib/serverpilot exists with the
// canonical permissions: mode 2770 (rwx for owner + group, plus the
// SETGID bit), owner root:deploy. The setgid bit on the directory makes
// every file created inside inherit the `deploy` group, so multiple
// deploy users can collaborate on the same registry without ownership
// flipping.
//
// When called as root: creates / repairs the directory.
// When called as non-root: does NOT attempt to mkdir (it would EACCES on
// /var/lib anyway). Instead, verifies the directory exists and is
// writable, and returns a friendly error pointing to `sudo sp setup`
// otherwise.
//
// This split lets the daemon (root, via systemd) provision the directory
// on startup, while CI/CD invocations of `sp port` (non-root deploy
// users) don't need elevation as long as they're members of the
// `deploy` group.
func ensureBaseDir() error {
	info, err := os.Stat(baseDir)
	if err == nil && info.IsDir() {
		if os.Geteuid() == 0 {
			return repairBaseDir()
		}
		return verifyExistingBaseDirAccessible()
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot stat %s: %w", baseDir, err)
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("%s does not exist — run `sudo sp setup` (or `sudo sp start`) once on this server to provision it", baseDir)
	}

	// We are root. Create the directory and set canonical ownership.
	if err := os.MkdirAll(baseDir, 0o2770); err != nil {
		return fmt.Errorf("cannot create %s: %w", baseDir, err)
	}
	return repairBaseDir()
}

func repairBaseDir() error {
	// chown root:deploy if the deploy group exists. If it doesn't yet,
	// fall back to root:root with mode 0700 — `sp setup` (or the first
	// `sp users create`) creates the deploy group, after which a later
	// invocation will fix the perms.
	deployGid, deployErr := lookupDeployGID()
	if deployErr == nil {
		if err := os.Chown(baseDir, 0, deployGid); err != nil {
			return fmt.Errorf("cannot chown %s: %w", baseDir, err)
		}
		if err := os.Chmod(baseDir, 0o2770); err != nil {
			return fmt.Errorf("cannot chmod %s: %w", baseDir, err)
		}
		for _, path := range []string{registryPath(), lockPath()} {
			if err := repairRegistryFile(path, deployGid); err != nil {
				return err
			}
		}
		return nil
	}

	if err := os.Chown(baseDir, 0, 0); err != nil {
		return fmt.Errorf("cannot chown %s: %w", baseDir, err)
	}
	if err := os.Chmod(baseDir, 0o700); err != nil {
		return fmt.Errorf("cannot chmod %s: %w", baseDir, err)
	}
	return nil
}

// EnsureSetup is the exported entry point intended to be called once on
// daemon startup (where we run as root) so that `/var/lib/serverpilot`
// exists with the canonical perms before any non-root `sp port` invocation
// happens. It is idempotent and silent on success.
func EnsureSetup() error { return ensureBaseDir() }

// StartDetectedPortSync starts a lightweight background job for the daemon. It
// scans immediately, then once per day near local midnight. Allocation paths
// also scan on demand; this periodic pass keeps the registry warm for non-root
// deploy users whose shell may not be able to inspect Docker or Nginx.
func StartDetectedPortSync(logf func(string, ...interface{})) {
	dailySyncOnce.Do(func() {
		go func() {
			if err := SyncDetectedPorts(DefaultMinPort, DefaultMaxPort); err != nil && logf != nil {
				logf("portalloc: detected port sync warning: %v", err)
			}
			for {
				wait := time.Until(nextLocalMidnight(time.Now()))
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
					if err := SyncDetectedPorts(DefaultMinPort, DefaultMaxPort); err != nil && logf != nil {
						logf("portalloc: detected port sync warning: %v", err)
					}
				case <-dailySyncStopCh:
					timer.Stop()
					return
				}
			}
		}()
	})
}

func nextLocalMidnight(now time.Time) time.Time {
	y, m, d := now.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, now.Location())
}

func SyncDetectedPorts(minPort, maxPort int) error {
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return fmt.Errorf("invalid port range %d-%d", minPort, maxPort)
	}
	if err := ensureBaseDir(); err != nil {
		return err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	syncDetectedPortsLocked(reg, minPort, maxPort)
	return saveRegistry(reg)
}

func repairRegistryFile(path string, deployGid int) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", path)
	}
	if err := os.Chown(path, 0, deployGid); err != nil {
		return fmt.Errorf("cannot chown %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("cannot chmod %s: %w", path, err)
	}
	return nil
}

func verifyExistingBaseDirAccessible() error {
	if err := syscall.Access(baseDir, accessWX); err != nil {
		return fmt.Errorf("%s is not writable by this user — run `sudo sp start` or `sudo sp setup` once to repair ServerPilot deploy permissions, then reconnect SSH if the user was just added to the deploy group: %w", baseDir, err)
	}
	for _, path := range []string{registryPath(), lockPath()} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot stat %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", path)
		}
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("%s is not writable by this user — run `sudo sp start` or `sudo sp setup` once to repair ServerPilot deploy permissions, then reconnect SSH if the user was just added to the deploy group: %w", path, err)
		}
		_ = f.Close()
	}
	return nil
}

// lookupDeployGID finds the GID of the `deploy` group via /etc/group
// (os/user uses NSS — same caveats as elsewhere in the codebase). Returns
// an error if the group does not exist yet, in which case the caller
// should fall back to root-only perms.
func lookupDeployGID() (int, error) {
	g, err := user.LookupGroup(deployGroupName)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, err
	}
	return gid, nil
}

// Reservation is a single port lock entry persisted to disk.
type Reservation struct {
	Port      int       `json:"port"`
	LockedAt  time.Time `json:"locked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Owner     string    `json:"owner,omitempty"`
}

// registry holds all active Reservations.
type registry struct {
	Reservations []Reservation `json:"reservations"`
}

// fileMu serialises access to the registry file within the same process.
// Cross-process safety is handled by advisory file locking (see lockFile).
var fileMu sync.Mutex

// Allocate finds the first available port in [minPort, maxPort], locks it
// for lockTTL, persists the lock, and returns the port number.
//
// "Available" means:
//  1. Not currently bound by any process (verified by attempting net.Listen).
//  2. Not reserved in the registry (i.e. not handed out to another caller
//     within the last minute).
func Allocate(minPort, maxPort int) (int, error) {
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return 0, fmt.Errorf("invalid port range %d-%d", minPort, maxPort)
	}

	if err := ensureBaseDir(); err != nil {
		return 0, err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return 0, fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	syncDetectedPortsLocked(reg, minPort, maxPort)
	if err := saveRegistry(reg); err != nil {
		return 0, fmt.Errorf("failed to persist detected ports: %w", err)
	}
	now := time.Now()

	reserved := make(map[int]bool, len(reg.Reservations))
	var alive []Reservation
	for _, r := range reg.Reservations {
		if r.Owner != "" || now.Before(r.ExpiresAt) {
			reserved[r.Port] = true
			alive = append(alive, r)
		}
	}
	reg.Reservations = alive

	for port := minPort; port <= maxPort; port++ {
		if reserved[port] {
			continue
		}
		if !isPortFree(port) {
			continue
		}

		reg.Reservations = append(reg.Reservations, Reservation{
			Port:      port,
			LockedAt:  now,
			ExpiresAt: now.Add(lockTTL),
		})
		if err := saveRegistry(reg); err != nil {
			return 0, fmt.Errorf("failed to persist reservation: %w", err)
		}
		return port, nil
	}

	return 0, fmt.Errorf("no available port in range %d-%d", minPort, maxPort)
}

// ReserveOwner returns a port permanently assigned to owner. If owner already
// has a reservation and the port is not bound, the same port is returned. This
// is intended for managed resources such as container replicas, where the port
// must remain reserved across restarts or brief downtime.
func ReserveOwner(owner string, minPort, maxPort int) (int, error) {
	if owner == "" || len(owner) > 128 {
		return 0, fmt.Errorf("invalid reservation owner")
	}
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return 0, fmt.Errorf("invalid port range %d-%d", minPort, maxPort)
	}
	if err := ensureBaseDir(); err != nil {
		return 0, err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return 0, fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	syncDetectedPortsLocked(reg, minPort, maxPort)
	if err := saveRegistry(reg); err != nil {
		return 0, fmt.Errorf("failed to persist detected ports: %w", err)
	}
	now := time.Now()
	reserved := make(map[int]string, len(reg.Reservations))
	var alive []Reservation
	ownerIdx := -1
	for _, r := range reg.Reservations {
		if r.Owner != "" || now.Before(r.ExpiresAt) {
			if r.Owner == owner {
				ownerIdx = len(alive)
			}
			reserved[r.Port] = r.Owner
			alive = append(alive, r)
		}
	}
	reg.Reservations = alive
	if ownerIdx >= 0 {
		r := reg.Reservations[ownerIdx]
		if isPortFree(r.Port) {
			r.LockedAt = now
			r.ExpiresAt = time.Time{}
			reg.Reservations[ownerIdx] = r
			if err := saveRegistry(reg); err != nil {
				return 0, fmt.Errorf("failed to persist reservation: %w", err)
			}
			return r.Port, nil
		}
		reg.Reservations = append(reg.Reservations[:ownerIdx], reg.Reservations[ownerIdx+1:]...)
		delete(reserved, r.Port)
	}

	for port := minPort; port <= maxPort; port++ {
		if _, ok := reserved[port]; ok {
			continue
		}
		if !isPortFree(port) {
			continue
		}
		reg.Reservations = append(reg.Reservations, Reservation{
			Port:      port,
			LockedAt:  now,
			ExpiresAt: time.Time{},
			Owner:     owner,
		})
		if err := saveRegistry(reg); err != nil {
			return 0, fmt.Errorf("failed to persist reservation: %w", err)
		}
		return port, nil
	}
	return 0, fmt.Errorf("no available port in range %d-%d", minPort, maxPort)
}

func ReleaseOwner(owner string) error {
	if owner == "" {
		return nil
	}
	if err := ensureBaseDir(); err != nil {
		return err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	next := reg.Reservations[:0]
	for _, r := range reg.Reservations {
		if r.Owner != owner {
			next = append(next, r)
		}
	}
	reg.Reservations = next
	return saveRegistry(reg)
}

func AssignOwnerPort(owner string, port int) error {
	if owner == "" || len(owner) > 128 {
		return fmt.Errorf("invalid reservation owner")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if err := ensureBaseDir(); err != nil {
		return err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	now := time.Now()
	next := reg.Reservations[:0]
	for _, r := range reg.Reservations {
		if r.Owner == owner {
			continue
		}
		if r.Port == port && r.Owner != "" {
			return fmt.Errorf("port already reserved by another owner")
		}
		if r.Port == port {
			continue
		}
		next = append(next, r)
	}
	reg.Reservations = append(next, Reservation{
		Port:      port,
		LockedAt:  now,
		ExpiresAt: time.Time{},
		Owner:     owner,
	})
	return saveRegistry(reg)
}

// ListReservations returns all non-expired Reservations (useful for debugging).
func ListReservations() []Reservation {
	if err := ensureBaseDir(); err != nil {
		return nil
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return nil
	}
	defer unlock()

	reg := loadRegistry()
	now := time.Now()
	var alive []Reservation
	for _, r := range reg.Reservations {
		if r.Owner != "" || now.Before(r.ExpiresAt) {
			alive = append(alive, r)
		}
	}
	return alive
}

func syncDetectedPortsLocked(reg *registry, minPort, maxPort int) {
	detected := make(map[int]string)
	var refreshedPrefixes []string
	if dockerPorts, ok := detectDockerPorts(); ok {
		refreshedPrefixes = append(refreshedPrefixes, detectedDockerOwnerPrefix)
		for port, owner := range dockerPorts {
			if port >= minPort && port <= maxPort {
				detected[port] = owner
			}
		}
	}
	if nginxPorts, ok := detectNginxProxyPorts(); ok {
		refreshedPrefixes = append(refreshedPrefixes, detectedNginxOwnerPrefix)
		for port, owner := range nginxPorts {
			if port >= minPort && port <= maxPort {
				if _, exists := detected[port]; !exists {
					detected[port] = owner
				}
			}
		}
	}
	applyDetectedReservations(reg, detected, refreshedPrefixes, time.Now())
}

func applyDetectedReservations(reg *registry, detected map[int]string, refreshedPrefixes []string, now time.Time) {
	next := reg.Reservations[:0]
	reserved := make(map[int]bool, len(reg.Reservations))
	for _, r := range reg.Reservations {
		if detectedOwnerWasRefreshed(r.Owner, refreshedPrefixes) {
			continue
		}
		if r.Owner != "" || now.Before(r.ExpiresAt) {
			reserved[r.Port] = true
			next = append(next, r)
		}
	}
	for port, owner := range detected {
		if reserved[port] {
			continue
		}
		next = append(next, Reservation{
			Port:      port,
			LockedAt:  now,
			ExpiresAt: time.Time{},
			Owner:     owner,
		})
	}
	reg.Reservations = next
}

func detectedOwnerWasRefreshed(owner string, refreshedPrefixes []string) bool {
	if !strings.HasPrefix(owner, detectedOwnerPrefix) {
		return false
	}
	for _, prefix := range refreshedPrefixes {
		if strings.HasPrefix(owner, prefix) {
			return true
		}
	}
	return false
}

type dockerInspectPortData struct {
	Name       string `json:"Name"`
	HostConfig struct {
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func detectDockerPorts() (map[int]string, bool) {
	out := map[int]string{}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return out, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	psOut, err := exec.CommandContext(ctx, dockerBin, "ps", "-aq", "--no-trunc").Output()
	if err != nil {
		return out, false
	}
	ids := strings.Fields(string(psOut))
	if len(ids) == 0 {
		return out, true
	}

	args := append([]string{"inspect"}, ids...)
	inspectOut, err := exec.CommandContext(ctx, dockerBin, args...).Output()
	if err != nil {
		return out, false
	}
	var containers []dockerInspectPortData
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		return out, false
	}
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		if name == "" {
			name = "container"
		}
		for _, bindings := range c.HostConfig.PortBindings {
			for _, b := range bindings {
				if port, ok := parsePort(b.HostPort); ok {
					out[port] = detectedDockerOwnerPrefix + name
				}
			}
		}
		for _, bindings := range c.NetworkSettings.Ports {
			for _, b := range bindings {
				if port, ok := parsePort(b.HostPort); ok {
					out[port] = detectedDockerOwnerPrefix + name
				}
			}
		}
	}
	return out, true
}

func detectNginxProxyPorts() (map[int]string, bool) {
	out := map[int]string{}
	const sitesAvailableDir = "/etc/nginx/sites-available"
	entries, err := os.ReadDir(sitesAvailableDir)
	if err != nil {
		return out, false
	}
	baseAbs, err := filepath.Abs(sitesAvailableDir)
	if err != nil {
		return out, false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(sitesAvailableDir, entry.Name())
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(baseAbs, pathAbs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			continue
		}
		info, err := os.Lstat(pathAbs)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(pathAbs)
		if err != nil {
			continue
		}
		matches := proxyPortRegex.FindAllStringSubmatch(string(data), -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			if port, ok := parsePort(match[1]); ok {
				out[port] = detectedNginxOwnerPrefix + entry.Name()
			}
		}
	}
	return out, true
}

func parsePort(value string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// isPortFree tries to bind on TCP 0.0.0.0:port. If the bind succeeds the
// port is free; the listener is closed immediately.
func isPortFree(port int) bool {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// ── Registry persistence ─────────────────────────────────────────────────

// loadRegistry reads the registry file, refusing to follow symlinks.
func loadRegistry() *registry {
	f, err := os.OpenFile(registryPath(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return &registry{}
	}
	defer f.Close()

	var reg registry
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		// Corrupted or wrong-shape file — start fresh.
		return &registry{}
	}
	return &reg
}

// saveRegistry writes the registry atomically: create a temp file in the
// SAME directory, fsync, then rename. The temp file is created with
// CreateTemp so its name is unpredictable to other processes.
//
// The file mode is 0660 (group rw) so any user in the `deploy` group can
// update the registry — necessary so non-root `sp port` invocations from
// CI/CD scripts work. Group ownership is `deploy` automatically because
// the parent directory has the SETGID bit set (see ensureBaseDir).
func saveRegistry(reg *registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(baseDir, ".ports-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Ensure cleanup on any failure path.
	defer func() {
		// Remove the temp file if it still exists (rename succeeded → no-op).
		_ = os.Remove(tmpPath)
	}()

	// 0660 = owner + group rw. Group is `deploy` thanks to the setgid bit
	// on the parent directory. Other users have no access.
	if err := tmp.Chmod(0o660); err != nil {
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
	return os.Rename(tmpPath, registryPath())
}
