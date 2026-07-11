package compose

import (
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

func indexOf(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}
