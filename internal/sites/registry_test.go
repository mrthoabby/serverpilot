package sites

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrthoabby/serverpilot/internal/templates"
)

func withTestRegistry(t *testing.T, fn func()) {
	t.Helper()
	dir := t.TempDir()
	orig := registryRoot
	registryRoot = dir
	t.Cleanup(func() { registryRoot = orig })
	fn()
}

func TestRegistryUpsertDeleteByConfigName(t *testing.T) {
	withTestRegistry(t, func() {
		rec := SiteRecord{
			ID:         "id1",
			Domain:     "app.example.com",
			ConfigName: "app.example.com",
			Template:   templates.API,
			State:      StateActive,
			CreatedAt:  time.Now().UTC(),
		}
		if err := Upsert(rec); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		all, err := List()
		if err != nil || len(all) != 1 {
			t.Fatalf("list after upsert: len=%d err=%v", len(all), err)
		}
		if err := DeleteByConfigName("app.example.com"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		all, err = List()
		if err != nil || len(all) != 0 {
			t.Fatalf("expected empty registry, got %#v err=%v", all, err)
		}
		if _, err := os.Stat(filepath.Join(registryRoot, registryName)); err != nil {
			t.Fatalf("registry file missing: %v", err)
		}
	})
}
