package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeProjectStrictRequiresSPPortVars(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "shop")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filepath.Join(opt, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	LockManagedAppsRootForTest(t, root)

	res, err := AnalyzeProjectStrict("shop", opt, "docker-compose.yml")
	if err != nil {
		t.Fatalf("AnalyzeProjectStrict: %v", err)
	}
	if res.CanDeploy {
		t.Fatal("expected hardcoded host port to block deploy")
	}
}

func TestAnalyzeProjectAcceptsSPComposePort(t *testing.T) {
	root := t.TempDir()
	opt := filepath.Join(root, "shop")
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "${SP_COMPOSE_PORT}:80"
`
	if err := os.WriteFile(filepath.Join(opt, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	LockManagedAppsRootForTest(t, root)

	res, err := AnalyzeProjectStrict("shop", opt, "docker-compose.yml")
	if err != nil {
		t.Fatalf("AnalyzeProjectStrict: %v", err)
	}
	if !res.CanDeploy {
		t.Fatalf("expected deployable project, blocking=%v", res.Blocking)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0].EnvVar != DefaultEndpointEnvVar {
		t.Fatalf("unexpected endpoints: %#v", res.Endpoints)
	}
}
