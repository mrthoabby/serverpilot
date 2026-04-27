package portalloc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
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
//   1. Move the registry into /var/lib/serverpilot/ (root-owned, 0700).
//      Non-root users cannot create or replace entries inside this directory.
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
)

func registryPath() string { return filepath.Join(baseDir, registryName) }
func lockPath() string     { return filepath.Join(baseDir, lockName) }

// ensureBaseDir creates /var/lib/serverpilot with mode 0700 owned by the
// running process (which is root). Idempotent.
func ensureBaseDir() error {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", baseDir, err)
	}
	// Tighten perms in case a previous invocation created it with a wider mode.
	if err := os.Chmod(baseDir, 0o700); err != nil {
		return fmt.Errorf("cannot chmod %s: %w", baseDir, err)
	}
	return nil
}

// Reservation is a single port lock entry persisted to disk.
type Reservation struct {
	Port      int       `json:"port"`
	LockedAt  time.Time `json:"locked_at"`
	ExpiresAt time.Time `json:"expires_at"`
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
	now := time.Now()

	reserved := make(map[int]bool, len(reg.Reservations))
	var alive []Reservation
	for _, r := range reg.Reservations {
		if now.Before(r.ExpiresAt) {
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
		if now.Before(r.ExpiresAt) {
			alive = append(alive, r)
		}
	}
	return alive
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

	// Restrict perms BEFORE writing data.
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
	return os.Rename(tmpPath, registryPath())
}
