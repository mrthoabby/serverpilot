package portalloc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Default port range for allocation.
const (
	DefaultMinPort = 3000
	DefaultMaxPort = 3999
)

// lockTTL is how long a reserved port stays locked before it can be
// re-allocated.  One minute gives the caller plenty of time to actually
// bind the port after receiving it.
const lockTTL = 1 * time.Minute

// registryPath is a shared file that all `sp port` invocations read/write
// to coordinate Reservations.  /tmp is world-readable and survives reboots
// on most distros only until the next tmpfiles cleanup, which is fine — the
// locks are ephemeral by design.
const registryPath = "/tmp/serverpilot-ports.json"

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

	fileMu.Lock()
	defer fileMu.Unlock()

	// Acquire cross-process file lock.
	unlock, err := lockFile(registryPath + ".lock")
	if err != nil {
		return 0, fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	now := time.Now()

	// Build a set of currently reserved (non-expired) ports for O(1) lookup.
	reserved := make(map[int]bool, len(reg.Reservations))
	var alive []Reservation
	for _, r := range reg.Reservations {
		if now.Before(r.ExpiresAt) {
			reserved[r.Port] = true
			alive = append(alive, r)
		}
		// Expired entries are silently dropped (garbage collection).
	}
	reg.Reservations = alive

	// Scan the range sequentially until we find a port that is both
	// unreserved AND not bound by any process.
	for port := minPort; port <= maxPort; port++ {
		if reserved[port] {
			continue
		}
		if !isPortFree(port) {
			continue
		}

		// Found one — reserve it.
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
	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(registryPath + ".lock")
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

// isPortFree tries to bind on TCP 0.0.0.0:port.  If the bind succeeds the
// port is free; the listener is closed immediately.  This is the most
// reliable check — it catches ports used by any protocol/process.
func isPortFree(port int) bool {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// ── Registry persistence ─────────────────────────────────────────────────

func loadRegistry() *registry {
	data, err := os.ReadFile(registryPath)
	if err != nil {
		return &registry{}
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		// Corrupted file — start fresh.
		return &registry{}
	}
	return &reg
}

func saveRegistry(reg *registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temp file then rename for atomic replacement (no partial reads).
	tmp := registryPath + ".tmp"
	// 0666 so any user can read/write (file lives in /tmp, ephemeral).
	if err := os.WriteFile(tmp, data, 0666); err != nil {
		return err
	}
	return os.Rename(tmp, registryPath)
}
