package permissions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindBinaryDoesNotCacheMisses(t *testing.T) {
	resetBinCache()

	dir := t.TempDir()
	candidate := filepath.Join(dir, "setfacl")

	if got := findBinary("test-setfacl", candidate); got != "" {
		t.Fatalf("findBinary before file exists = %q, want empty", got)
	}

	if err := os.WriteFile(candidate, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	if got := findBinary("test-setfacl", candidate); got != candidate {
		t.Fatalf("findBinary after file exists = %q, want %q", got, candidate)
	}
}

func TestFindBinaryCachesPositiveResult(t *testing.T) {
	resetBinCache()

	dir := t.TempDir()
	first := filepath.Join(dir, "gpasswd-first")
	second := filepath.Join(dir, "gpasswd-second")
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	if got := findBinary("test-gpasswd", first, second); got != first {
		t.Fatalf("first findBinary = %q, want %q", got, first)
	}

	if err := os.Remove(first); err != nil {
		t.Fatalf("remove first candidate: %v", err)
	}

	if got := findBinary("test-gpasswd", first, second); got != first {
		t.Fatalf("cached findBinary = %q, want still-cached %q", got, first)
	}
}
