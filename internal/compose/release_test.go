package compose

import (
	"testing"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

func TestReleaseServiceRequiresImageRef(t *testing.T) {
	cleanup := SetRegistryRootForTests(t.TempDir())
	defer cleanup()

	err := ReleaseService(ReleaseRequest{Name: "shop", Service: "app"}, nil)
	if err == nil || err.Error() != "IMAGE_REF is required" {
		t.Fatalf("expected IMAGE_REF error, got %v", err)
	}
}

func TestReleaseServiceRequiresCompose(t *testing.T) {
	if deps.ComposeAvailable() {
		t.Skip("compose is installed on this host")
	}
	cleanup := SetRegistryRootForTests(t.TempDir())
	defer cleanup()

	err := ReleaseService(ReleaseRequest{
		Name:     "shop",
		Service:  "app",
		ImageRef: "ghcr.io/org/app:v1.0.0",
	}, nil)
	if err == nil {
		t.Fatal("expected error when compose is missing")
	}
}
