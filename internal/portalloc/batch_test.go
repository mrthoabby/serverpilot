package portalloc

import "testing"

func TestReserveOwnersAtomicRollback(t *testing.T) {
	root := t.TempDir()
	setRegistryRootForTests(t, root)

	first, err := ReserveOwners([]PortOwnerRequest{{Owner: "compose:test:gen:web:8080"}}, 3100, 3110)
	if err != nil {
		t.Fatalf("ReserveOwners: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("expected one reservation, got %v", first)
	}

	_, err = ReserveOwners([]PortOwnerRequest{
		{Owner: "compose:test:gen2:web:8080"},
		{Owner: "compose:test:gen2:api:3000"},
	}, 3100, 3101)
	if err == nil {
		t.Fatal("expected failure when only one port remains")
	}

	second, err := ReserveOwners([]PortOwnerRequest{{Owner: "compose:test:gen:web:8080"}}, 3100, 3110)
	if err != nil {
		t.Fatalf("re-reserve existing owner: %v", err)
	}
	if second["compose:test:gen:web:8080"] != first["compose:test:gen:web:8080"] {
		t.Fatalf("expected same port on re-reserve")
	}
}

func setRegistryRootForTests(t *testing.T, root string) {
	t.Helper()
	oldBase := baseDir
	baseDir = root
	t.Cleanup(func() { baseDir = oldBase })
	if err := EnsureSetup(); err != nil {
		t.Fatalf("EnsureSetup: %v", err)
	}
}
