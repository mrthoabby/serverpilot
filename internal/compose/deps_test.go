package compose

import (
	"os"
	"path/filepath"
	"strings"
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
    depends_on:
      mongo:
        condition: service_healthy
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
	if len(byName["migrate"].DependsOn) != 1 || byName["migrate"].DependsOn[0] != "mongo" {
		t.Fatalf("expected migrate dependency to be parsed, got %#v", byName["migrate"].DependsOn)
	}
}

func TestAnalyzeProjectRejectsInvalidDependencyReference(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "shop")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	composeYAML := `services:
  job:
    image: busybox:stable
    restart: "no"
    depends_on:
      - " database "
  database:
    image: busybox:stable
`
	if err := os.WriteFile(filepath.Join(opt, "docker-compose.yml"), []byte(composeYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	LockManagedAppsRootForTest(t, root)

	result, err := AnalyzeProject("shop", opt, "docker-compose.yml")
	if err != nil {
		t.Fatalf("AnalyzeProject: %v", err)
	}
	if result.CanDeploy {
		t.Fatalf("expected malformed depends_on reference to block deployment: %#v", result)
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

func TestServiceDependencyNamesUsesTransitiveComposeGraph(t *testing.T) {
	analysis := &AnalyzeResult{
		Services: []ServiceSpec{
			{Name: "api", DependsOn: []string{"job", "cache"}},
			{Name: "job", OneShot: true, DependsOn: []string{"database"}},
			{Name: "cache"},
			{Name: "database", DependsOn: []string{"storage"}},
			{Name: "storage"},
			{Name: "unrelated"},
		},
	}
	got := ServiceDependencyNames(analysis, "job")
	want := []string{"database", "storage"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestPlanDependencyEnsure(t *testing.T) {
	states := []ServiceRuntimeState{
		{Service: "healthy-service", State: "running", Health: "healthy"},
		{Service: "unhealthy-service", State: "running", Health: "unhealthy"},
		{Service: "stopped-service", State: "exited"},
		{Service: "missing-service", State: "missing"},
		{Service: "starting-service", State: "running", Health: "starting"},
	}
	healthy, start, recreate := planDependencyEnsure(states)
	if len(healthy) != 1 || healthy[0] != "healthy-service" {
		t.Fatalf("healthy: got %v", healthy)
	}
	if len(recreate) != 1 || recreate[0] != "unhealthy-service" {
		t.Fatalf("recreate: got %v", recreate)
	}
	wantStart := []string{"stopped-service", "missing-service", "starting-service"}
	if len(start) != len(wantStart) {
		t.Fatalf("start: got %v want %v", start, wantStart)
	}
	for i := range wantStart {
		if start[i] != wantStart[i] {
			t.Fatalf("start: got %v want %v", start, wantStart)
		}
	}
}

func TestFormatDependencyEnsureFailureIsServiceAgnostic(t *testing.T) {
	got := formatDependencyEnsureFailure([]ServiceRuntimeState{
		{Service: "queue", State: "running", Health: "unhealthy"},
		{Service: "worker", State: "exited"},
		{Service: "api", State: "running", Health: "healthy"},
	})
	want := "queue(state=running, health=unhealthy), worker(state=exited, health=-)"
	if !strings.Contains(got, want) {
		t.Fatalf("got %q, expected it to contain %q", got, want)
	}
	if strings.Contains(strings.ToLower(got), "mongo") || strings.Contains(strings.ToLower(got), "redis") {
		t.Fatalf("diagnostic must not assume service technology: %q", got)
	}
}

func TestWorstRuntimeStateDoesNotHideUnhealthyReplica(t *testing.T) {
	got := worstRuntimeState(
		ServiceRuntimeState{Service: "api", State: "running", Health: "healthy"},
		ServiceRuntimeState{Service: "api", State: "running", Health: "unhealthy"},
	)
	if got.State != "running" || got.Health != "unhealthy" {
		t.Fatalf("got %#v", got)
	}

	got = worstRuntimeState(
		ServiceRuntimeState{Service: "api", State: "running", Health: "healthy"},
		ServiceRuntimeState{Service: "api", State: "exited"},
	)
	if got.State != "exited" {
		t.Fatalf("got %#v", got)
	}
}
