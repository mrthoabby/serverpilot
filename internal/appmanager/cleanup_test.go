package appmanager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupPreproductionStateRunsOnlyOnce(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "appmanager")
	if err := os.MkdirAll(filepath.Join(stateDir, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "appmanager.db"),
		filepath.Join(stateDir, "master.key"),
		filepath.Join(stateDir, "tmp", "runtime.env"),
	} {
		if err := os.WriteFile(path, []byte("prototype"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupPreproductionState(stateDir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "appmanager.db"),
		filepath.Join(stateDir, "master.key"),
		filepath.Join(stateDir, "tmp"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("prototype state still exists at %s", path)
		}
	}
	markerPath := filepath.Join(stateDir, previewCleanupMarker)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if markerInfo.Mode().Perm() != 0o600 {
		t.Fatalf("cleanup marker permissions = %o, want 600", markerInfo.Mode().Perm())
	}
	sentinel := filepath.Join(stateDir, "created-after-cleanup")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPreproductionState(stateDir); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "keep" {
		t.Fatalf("second startup removed current state: value=%q err=%v", value, err)
	}
}

func TestCleanupPreproductionStateRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "appmanager")
	if err := os.Symlink(target, stateDir); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPreproductionState(stateDir); err == nil {
		t.Fatal("symlink cleanup directory must be rejected")
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "keep" {
		t.Fatalf("symlink target was modified: value=%q err=%v", value, err)
	}
}
