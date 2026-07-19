package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeProjectMarksOneShotServices(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "shop")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	composeYAML := `services:
  app:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "${SP_COMPOSE_PORT}:80"
  migrate:
    image: nginx:alpine
    restart: "no"
  mongo:
    image: mongo:7
    restart: unless-stopped
`
	if err := os.WriteFile(filepath.Join(opt, "docker-compose.yml"), []byte(composeYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	LockManagedAppsRootForTest(t, root)

	res, err := AnalyzeProjectStrict("shop", opt, "docker-compose.yml")
	if err != nil {
		t.Fatalf("AnalyzeProjectStrict: %v", err)
	}
	byName := map[string]ServiceSpec{}
	for _, svc := range res.Services {
		byName[svc.Name] = svc
	}
	if !byName["migrate"].OneShot {
		t.Fatalf("expected migrate to be one-shot, got %#v", byName["migrate"])
	}
	if byName["app"].OneShot || byName["mongo"].OneShot {
		t.Fatalf("expected app/mongo to be long-running: %#v", byName)
	}
}

func TestDependencyServiceNamesExcludesTargetAndOneShot(t *testing.T) {
	analysis := &AnalyzeResult{
		Services: []ServiceSpec{
			{Name: "web", Restart: "unless-stopped"},
			{Name: "web-migrate", Restart: "no", OneShot: true},
			{Name: "mongo", Restart: "unless-stopped"},
			{Name: "redis-cache", Restart: "unless-stopped"},
			{Name: "minio-init", Restart: "no", OneShot: true},
		},
	}
	got := DependencyServiceNames(analysis, "web")
	want := []string{"mongo", "redis-cache"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
