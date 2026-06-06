package portalloc

import (
	"testing"
	"time"
)

func TestApplyDetectedReservationsPreservesStrongLocks(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	reg := &registry{Reservations: []Reservation{
		{
			Port:      3000,
			LockedAt:  now.Add(-time.Hour),
			ExpiresAt: time.Time{},
			Owner:     "replica:ui",
		},
		{
			Port:      3001,
			LockedAt:  now.Add(-time.Hour),
			ExpiresAt: time.Time{},
			Owner:     "detected:docker:old",
		},
		{
			Port:      3005,
			LockedAt:  now.Add(-time.Hour),
			ExpiresAt: time.Time{},
			Owner:     "detected:nginx:site.conf",
		},
		{
			Port:      3002,
			LockedAt:  now.Add(-10 * time.Second),
			ExpiresAt: now.Add(time.Minute),
		},
		{
			Port:      3003,
			LockedAt:  now.Add(-2 * time.Minute),
			ExpiresAt: now.Add(-time.Minute),
		},
	}}

	applyDetectedReservations(reg, map[int]string{
		3000: "detected:docker:ui",
		3004: "detected:docker:api",
	}, []string{detectedDockerOwnerPrefix}, now)

	owners := map[int]string{}
	for _, r := range reg.Reservations {
		if _, exists := owners[r.Port]; exists {
			t.Fatalf("duplicate reservation for port %d: %#v", r.Port, reg.Reservations)
		}
		owners[r.Port] = r.Owner
	}

	if owners[3000] != "replica:ui" {
		t.Fatalf("expected persistent owner on 3000 to survive, got %q", owners[3000])
	}
	if _, ok := owners[3001]; ok {
		t.Fatalf("expected stale detected reservation on 3001 to be removed, got %q", owners[3001])
	}
	if _, ok := owners[3002]; !ok {
		t.Fatal("expected unexpired temporary lock on 3002 to survive")
	}
	if _, ok := owners[3003]; ok {
		t.Fatal("expected expired temporary lock on 3003 to be removed")
	}
	if owners[3004] != "detected:docker:api" {
		t.Fatalf("expected current detected reservation on 3004, got %q", owners[3004])
	}
	if owners[3005] != "detected:nginx:site.conf" {
		t.Fatalf("expected unrefreshed nginx detected reservation on 3005 to survive, got %q", owners[3005])
	}
}

func TestParsePort(t *testing.T) {
	tests := map[string]bool{
		"3000":  true,
		" 80 ":  true,
		"0":     false,
		"65536": false,
		"abc":   false,
	}
	for value, want := range tests {
		_, got := parsePort(value)
		if got != want {
			t.Fatalf("parsePort(%q) valid=%v, want %v", value, got, want)
		}
	}
}
