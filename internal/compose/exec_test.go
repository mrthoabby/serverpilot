package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpArgsEnvFileBeforeSubcommand(t *testing.T) {
	r := Runner{
		ComposeFile:    "/opt/app/docker-compose.yml",
		ComposeProject: "app",
		ProjectEnvFile: "/opt/app/prod.env",
		EnvFile:        "/var/lib/serverpilot/compose/app/gen/serverpilot.env",
		OverrideFile:   "/var/lib/serverpilot/compose/app/gen/serverpilot.override.yml",
	}
	args, err := r.upArgs()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	upIdx := indexOf(args, "up")
	envIdx := indexOf(args, "--env-file")
	if upIdx < 0 || envIdx < 0 {
		t.Fatalf("expected up and --env-file in %v", args)
	}
	if envIdx > upIdx {
		t.Fatalf("--env-file must precede up subcommand, got: %s", joined)
	}
}

func TestRuntimeEnvDoesNotReinjectEnvFileValues(t *testing.T) {
	root := t.TempDir()
	projectEnv := filepath.Join(root, "prod.env")
	generationEnv := filepath.Join(root, "serverpilot.env")
	if err := os.WriteFile(projectEnv, []byte("DISCOVERY_MONGO_ROOT_PASSWORD=\"quoted-secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(generationEnv, []byte("SP_COMPOSE_PORT=12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Runner{
		ProjectEnvFile: projectEnv,
		EnvFile:        generationEnv,
	}
	env := r.runtimeEnv("registry.example/app:v1")
	for _, item := range env {
		if strings.HasPrefix(item, "DISCOVERY_MONGO_ROOT_PASSWORD=") {
			t.Fatalf("runtime env must not duplicate values parsed by Compose: %v", env)
		}
	}
	if indexOf(env, "IMAGE_REF=registry.example/app:v1") < 0 {
		t.Fatalf("runtime env must include explicit image override: %v", env)
	}
}

func indexOf(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}

func TestRenderPortOverrideYAMLUsesOverrideMerge(t *testing.T) {
	out := RenderPortOverrideYAML([]Endpoint{
		{Service: "web", ContainerPort: "8080", EnvVar: "SP_COMPOSE_PORT_WEB_8080"},
	})
	body := string(out)
	if !strings.Contains(body, "ports: !override") {
		t.Fatalf("expected !override merge tag, got:\n%s", body)
	}
	if !strings.Contains(body, "127.0.0.1:${SP_COMPOSE_PORT_WEB_8080}:8080") {
		t.Fatalf("expected localhost bind, got:\n%s", body)
	}
}
