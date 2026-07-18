package portalloc

import (
	"strings"
	"testing"
	"time"
)

func TestReserveOwnerReusesExistingPort(t *testing.T) {
	root := t.TempDir()
	setRegistryRootForTests(t, root)

	first, err := ReserveOwner("docker:api:8080/tcp", 3100, 3110)
	if err != nil {
		t.Fatalf("ReserveOwner first: %v", err)
	}
	second, err := ReserveOwner("docker:api:8080/tcp", 3100, 3110)
	if err != nil {
		t.Fatalf("ReserveOwner second: %v", err)
	}
	if first != second {
		t.Fatalf("expected same port, got %d then %d", first, second)
	}
}

func TestReserveOwnersRollbackKeepsReusedOwner(t *testing.T) {
	root := t.TempDir()
	setRegistryRootForTests(t, root)

	stable := ComposeStableOwner("shop", "web", "8080", "tcp")
	if err := AssignOwnerPort(stable, 3100); err != nil {
		t.Fatalf("AssignOwnerPort: %v", err)
	}

	_, err := ReserveOwners([]PortOwnerRequest{
		{Owner: stable},
		{Owner: "compose:shop:api:3000/tcp"},
	}, 3100, 3100)
	if err == nil {
		t.Fatal("expected failure when only one port remains and second owner is new")
	}

	port, err := ReserveOwner(stable, 3100, 3110)
	if err != nil {
		t.Fatalf("re-reserve stable owner: %v", err)
	}
	if port != 3100 {
		t.Fatalf("expected stable port 3100, got %d", port)
	}
}

func TestTransferOwnerPreservesPort(t *testing.T) {
	root := t.TempDir()
	setRegistryRootForTests(t, root)

	from := ComposeOwner("app", "g1", "web", "80")
	to := ComposeStableOwner("app", "web", "80", "tcp")
	if err := AssignOwnerPort(from, 3200); err != nil {
		t.Fatalf("AssignOwnerPort: %v", err)
	}
	if err := TransferOwner(from, to); err != nil {
		t.Fatalf("TransferOwner: %v", err)
	}
	port, err := ReserveOwner(to, 3000, 3999)
	if err != nil {
		t.Fatalf("ReserveOwner stable: %v", err)
	}
	if port != 3200 {
		t.Fatalf("expected transferred port 3200, got %d", port)
	}
}

func TestOwnerGraceExpiration(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	reg := &registry{Reservations: []Reservation{
		{
			Port:          3300,
			LockedAt:      now.Add(-20 * 24 * time.Hour),
			LastActiveAt:  now.Add(-20 * 24 * time.Hour),
			InactiveSince: now.Add(-15 * 24 * time.Hour),
			Owner:         "docker:api:8080/tcp",
		},
		{
			Port:          3301,
			LockedAt:      now.Add(-2 * 24 * time.Hour),
			LastActiveAt:  now.Add(-2 * 24 * time.Hour),
			InactiveSince: now.Add(-24 * time.Hour),
			Owner:         "docker:api:8081/tcp",
		},
	}}

	pruneReservationsLocked(reg, now)
	if len(reg.Reservations) != 1 {
		t.Fatalf("expected one held reservation, got %#v", reg.Reservations)
	}
	if reg.Reservations[0].Port != 3301 {
		t.Fatalf("expected port 3301 to remain, got %d", reg.Reservations[0].Port)
	}
}

func TestComposeStableOwnerFormat(t *testing.T) {
	got := ComposeStableOwner("proj", "web", "8080", "tcp")
	want := "compose:proj:web:8080/tcp"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestReleaseOwnersByPrefix(t *testing.T) {
	root := t.TempDir()
	setRegistryRootForTests(t, root)

	owners := []string{
		ComposeStableOwner("shop", "web", "8080", "tcp"),
		ComposeStableOwner("shop", "api", "3000", "tcp"),
		ComposeOwner("shop", "gen1", "web", "8080"),
		DockerOwner("api", "8080", "tcp"),
	}
	for i, owner := range owners {
		if err := AssignOwnerPort(owner, 3400+i); err != nil {
			t.Fatalf("AssignOwnerPort %s: %v", owner, err)
		}
	}
	ReleaseOwnersByPrefix("compose:shop:")
	for _, r := range ListReservations() {
		if strings.HasPrefix(r.Owner, "compose:shop:") {
			t.Fatalf("unexpected compose reservation: %#v", r)
		}
	}
	foundDocker := false
	for _, r := range ListReservations() {
		if r.Owner == owners[3] {
			foundDocker = true
			if r.Port != 3403 {
				t.Fatalf("expected docker owner on 3403, got %d", r.Port)
			}
		}
	}
	if !foundDocker {
		t.Fatal("expected docker owner to remain")
	}
}
