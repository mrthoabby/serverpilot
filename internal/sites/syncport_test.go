package sites

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrthoabby/serverpilot/internal/templates"
)

func TestRegistryHostPortForContainer(t *testing.T) {
	dir := t.TempDir()
	orig := registryRoot
	registryRoot = dir
	t.Cleanup(func() { registryRoot = orig })

	rec := SiteRecord{
		ID:            "site1",
		ContainerName: "discovery-admin-ui",
		HostPort:      3004,
		ContainerPort: 3000,
		Domain:        "admin.example.com",
		ConfigName:    "admin.example.com",
		Template:      templates.NextJS,
		State:         StateActive,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := Upsert(rec); err != nil {
		t.Fatal(err)
	}

	port, ok, err := RegistryHostPortForContainer("discovery-admin-ui")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || port != 3004 {
		t.Fatalf("port = %d ok=%v, want 3004 true", port, ok)
	}

	if _, err := os.Stat(filepath.Join(dir, registryName)); err != nil {
		t.Fatalf("registry file: %v", err)
	}
}
