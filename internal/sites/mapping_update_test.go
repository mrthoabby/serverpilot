package sites

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveManagedSite(t *testing.T) {
	dir := t.TempDir()
	registryRoot = dir
	t.Cleanup(func() { registryRoot = "/var/lib/serverpilot" })

	rec := SiteRecord{
		ID:            "site-1",
		Domain:        "app.example.com",
		ConfigName:    "app.example.com",
		ContainerName: "app",
		HostPort:      3004,
		ContainerPort: 3000,
		State:         StateActive,
	}
	if err := Upsert(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := ResolveManagedSite("site-1", "", "")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.Domain != rec.Domain {
		t.Fatalf("got domain %q", got.Domain)
	}

	got, err = ResolveManagedSite("", "app.example.com", "")
	if err != nil {
		t.Fatalf("by config: %v", err)
	}
	if got.ID != rec.ID {
		t.Fatalf("got id %q", got.ID)
	}

	got, err = ResolveManagedSite("", "", "app.example.com")
	if err != nil {
		t.Fatalf("by domain: %v", err)
	}
	if got.ID != rec.ID {
		t.Fatalf("got id %q", got.ID)
	}

	if _, err := ResolveManagedSite("", "", "missing.example.com"); err == nil {
		t.Fatal("expected missing site error")
	}

	if err := os.Remove(filepath.Join(dir, registryName)); err != nil {
		t.Fatalf("remove registry: %v", err)
	}
}
