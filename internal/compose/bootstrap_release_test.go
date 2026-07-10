package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedComposeReady(t *testing.T) {
	root := t.TempDir()
	ManagedAppsRoot = root
	t.Cleanup(func() { ManagedAppsRoot = "/opt" })

	if managedComposeReady("shop", "docker-compose.yml") {
		t.Fatal("expected missing compose")
	}
	appDir := filepath.Join(root, "shop")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "docker-compose.yml"), []byte("services:\n  app:\n    image: nginx\n    ports:\n      - \"${SP_COMPOSE_PORT}:80\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !managedComposeReady("shop", "docker-compose.yml") {
		t.Fatal("expected compose ready")
	}
}

func TestManagedProdEnvExists(t *testing.T) {
	root := t.TempDir()
	ManagedAppsRoot = root
	t.Cleanup(func() { ManagedAppsRoot = "/opt" })

	appDir := filepath.Join(root, "shop")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if managedProdEnvExists("shop") {
		t.Fatal("expected no env file")
	}
	if err := os.WriteFile(filepath.Join(appDir, "prod.env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !managedProdEnvExists("shop") {
		t.Fatal("expected prod.env")
	}
}
