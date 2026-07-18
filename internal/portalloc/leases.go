package portalloc

import (
	"fmt"
	"strings"
	"time"
)

// ownerGracePeriod is how long an inactive owned reservation is kept before
// the port may be reassigned to another owner.
const ownerGracePeriod = 14 * 24 * time.Hour

// ReservationInfo augments a reservation with derived lifecycle metadata.
type ReservationInfo struct {
	Reservation
	Status    string     `json:"status"`
	ReleaseAt *time.Time `json:"release_at,omitempty"`
}

// ReserveResult is returned by ReserveOwnerWithMeta.
type ReserveResult struct {
	Port    int
	Created bool
}

// ReserveOwnerWithMeta reserves or reuses a permanent owner-bound port.
func ReserveOwnerWithMeta(owner string, minPort, maxPort int) (ReserveResult, error) {
	if owner == "" || len(owner) > 128 {
		return ReserveResult{}, fmt.Errorf("invalid reservation owner")
	}
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return ReserveResult{}, fmt.Errorf("invalid port range %d-%d", minPort, maxPort)
	}
	if err := ensureBaseDir(); err != nil {
		return ReserveResult{}, err
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return ReserveResult{}, fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer unlock()

	reg := loadRegistry()
	syncDetectedPortsLocked(reg, minPort, maxPort)
	now := time.Now()
	pruneReservationsLocked(reg, now)

	port, created, err := reserveOwnerLocked(reg, owner, minPort, maxPort, now)
	if err != nil {
		return ReserveResult{}, err
	}
	if err := saveRegistry(reg); err != nil {
		return ReserveResult{}, fmt.Errorf("failed to persist reservation: %w", err)
	}
	return ReserveResult{Port: port, Created: created}, nil
}

func reserveOwnerLocked(reg *registry, owner string, minPort, maxPort int, now time.Time) (int, bool, error) {
	reserved := reservationIndex(reg, now)
	if idx, ok := reserved.byOwner[owner]; ok {
		r := normalizeOwnerReservation(reg.Reservations[idx], now)
		r = markOwnerActive(r, now)
		reg.Reservations[idx] = r
		return r.Port, false, nil
	}

	for port := minPort; port <= maxPort; port++ {
		if existingOwner, ok := reserved.byPort[port]; ok && existingOwner != owner {
			continue
		}
		if !isPortFree(port) {
			continue
		}
		reg.Reservations = append(reg.Reservations, Reservation{
			Port:         port,
			LockedAt:     now,
			LastActiveAt: now,
			Owner:        owner,
		})
		return port, true, nil
	}
	return 0, false, fmt.Errorf("no available port in range %d-%d", minPort, maxPort)
}

// TransferOwner moves a permanent reservation from one owner id to another while
// keeping the same host port.
func TransferOwner(fromOwner, toOwner string) error {
	if fromOwner == "" || toOwner == "" || len(toOwner) > 128 {
		return fmt.Errorf("invalid reservation owner")
	}
	if fromOwner == toOwner {
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
	now := time.Now()
	pruneReservationsLocked(reg, now)

	fromIdx, toIdx := -1, -1
	for i, r := range reg.Reservations {
		if r.Owner == fromOwner {
			fromIdx = i
		}
		if r.Owner == toOwner {
			toIdx = i
		}
	}
	if fromIdx < 0 {
		return nil
	}
	from := reg.Reservations[fromIdx]
	if toIdx >= 0 {
		reg.Reservations = append(reg.Reservations[:fromIdx], reg.Reservations[fromIdx+1:]...)
		return saveRegistry(reg)
	}
	from.Owner = toOwner
	from.LockedAt = now
	from = markOwnerActive(from, now)
	reg.Reservations[fromIdx] = from
	return saveRegistry(reg)
}

// ReleaseOwnersByPrefix releases every permanent owner whose id starts with prefix.
func ReleaseOwnersByPrefix(prefix string) {
	if prefix == "" {
		return
	}
	if err := ensureBaseDir(); err != nil {
		return
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	unlock, err := lockFile(lockPath())
	if err != nil {
		return
	}
	defer unlock()

	reg := loadRegistry()
	next := reg.Reservations[:0]
	for _, r := range reg.Reservations {
		if strings.HasPrefix(r.Owner, prefix) {
			continue
		}
		next = append(next, r)
	}
	reg.Reservations = next
	_ = saveRegistry(reg)
}

// ListReservationInfos returns active reservations with derived status metadata.
func ListReservationInfos() []ReservationInfo {
	raw := ListReservations()
	now := time.Now()
	out := make([]ReservationInfo, 0, len(raw))
	for _, r := range raw {
		status, releaseAt := reservationStatus(r, now)
		info := ReservationInfo{
			Reservation: r,
			Status:      status,
		}
		if !releaseAt.IsZero() {
			t := releaseAt
			info.ReleaseAt = &t
		}
		out = append(out, info)
	}
	return out
}

func reservationStatus(r Reservation, now time.Time) (string, time.Time) {
	if r.Owner == "" {
		return "temporary", r.ExpiresAt
	}
	if strings.HasPrefix(r.Owner, detectedOwnerPrefix) {
		return "detected", time.Time{}
	}
	if isPortListening(r.Port) {
		return "active", time.Time{}
	}
	if r.InactiveSince.IsZero() {
		return "held", time.Time{}
	}
	releaseAt := r.InactiveSince.Add(ownerGracePeriod)
	if now.Before(releaseAt) {
		return "held", releaseAt
	}
	return "expired", releaseAt
}

type reservationIndexView struct {
	byPort  map[int]string
	byOwner map[string]int
}

func reservationIndex(reg *registry, now time.Time) reservationIndexView {
	out := reservationIndexView{
		byPort:  make(map[int]string, len(reg.Reservations)),
		byOwner: make(map[string]int, len(reg.Reservations)),
	}
	for i, r := range reg.Reservations {
		if !reservationAlive(r, now) {
			continue
		}
		out.byPort[r.Port] = r.Owner
		if r.Owner != "" {
			out.byOwner[r.Owner] = i
		}
	}
	return out
}

func reservationAlive(r Reservation, now time.Time) bool {
	if r.Owner == "" {
		return now.Before(r.ExpiresAt)
	}
	return keepReservation(r, now)
}

func pruneReservationsLocked(reg *registry, now time.Time) {
	refreshOwnerActivityLocked(reg, now)
	next := reg.Reservations[:0]
	for _, r := range reg.Reservations {
		if keepReservation(r, now) {
			next = append(next, r)
		}
	}
	reg.Reservations = next
}

func refreshOwnerActivityLocked(reg *registry, now time.Time) {
	for i, r := range reg.Reservations {
		if r.Owner == "" || strings.HasPrefix(r.Owner, detectedOwnerPrefix) {
			continue
		}
		r = normalizeOwnerReservation(r, now)
		if isPortListening(r.Port) {
			r = markOwnerActive(r, now)
		} else if r.InactiveSince.IsZero() {
			r.InactiveSince = now
		}
		reg.Reservations[i] = r
	}
}

func keepReservation(r Reservation, now time.Time) bool {
	if r.Owner == "" {
		return now.Before(r.ExpiresAt)
	}
	if strings.HasPrefix(r.Owner, detectedOwnerPrefix) {
		return true
	}
	if isPortListening(r.Port) {
		return true
	}
	if r.InactiveSince.IsZero() {
		return true
	}
	if now.Sub(r.InactiveSince) < ownerGracePeriod {
		return true
	}
	return false
}

func normalizeOwnerReservation(r Reservation, now time.Time) Reservation {
	if r.Owner == "" || strings.HasPrefix(r.Owner, detectedOwnerPrefix) {
		return r
	}
	if r.LastActiveAt.IsZero() {
		r.LastActiveAt = r.LockedAt
		if r.LastActiveAt.IsZero() {
			r.LastActiveAt = now
		}
	}
	return r
}

func markOwnerActive(r Reservation, now time.Time) Reservation {
	r.LastActiveAt = now
	r.InactiveSince = time.Time{}
	return r
}

func isPortListening(port int) bool {
	return !isPortFree(port)
}

// PortForOwner returns the host port reserved for owner, if any.
func PortForOwner(owner string) (int, bool) {
	if owner == "" {
		return 0, false
	}
	for _, r := range ListReservations() {
		if r.Owner == owner {
			return r.Port, true
		}
	}
	return 0, false
}
