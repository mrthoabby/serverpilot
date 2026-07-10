package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveProjectRootRejectsEscape(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "app")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	LockManagedAppsRootForTest(t, root)

	got, err := ResolveProjectRoot(opt)
	if err != nil {
		t.Fatalf("ResolveProjectRoot: %v", err)
	}
	want, _ := filepath.EvalSymlinks(opt)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	outside := filepath.Join(root, "..", "outside")
	if _, err := ResolveProjectRoot(outside); err == nil {
		t.Fatal("expected escape to fail")
	}
}

func TestResolveComposeFileContained(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "app")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(opt, "docker-compose.yml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := ManagedAppsRoot
	ManagedAppsRoot = root
	t.Cleanup(func() { ManagedAppsRoot = old })

	got, err := ResolveComposeFile(opt, "docker-compose.yml")
	if err != nil {
		t.Fatalf("ResolveComposeFile: %v", err)
	}
	want, _ := filepath.EvalSymlinks(compose)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
