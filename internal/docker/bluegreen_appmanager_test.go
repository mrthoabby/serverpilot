package docker

import (
	"reflect"
	"testing"
)

func TestBuildBlueGreenRunArgsUsesManagedEnvFileInsteadOfInheritedEnvironment(t *testing.T) {
	runtime := containerRuntimeInspect{}
	runtime.Config.Env = []string{"SECRET=legacy", "LOG_LEVEL=debug"}
	args := buildBlueGreenRunArgs(runtime, "sp-orders-production__green", "ghcr.io/acme/sp-platform-orders@sha256:abc", 22001, "8080", "tcp", "/var/lib/serverpilot/appmanager/tmp/environment.env")
	wantPair := []string{"--env-file", "/var/lib/serverpilot/appmanager/tmp/environment.env"}
	found := false
	for i := 0; i+1 < len(args); i++ {
		if reflect.DeepEqual(args[i:i+2], wantPair) {
			found = true
		}
		if args[i] == "-e" {
			t.Fatal("inherited environment must not be copied when an app-manager env file is provided")
		}
	}
	if !found {
		t.Fatalf("managed environment file missing from docker arguments: %#v", args)
	}
}

func TestValidateAppManagerEnvFileRejectsOutsidePath(t *testing.T) {
	if err := validateAppManagerEnvFile("/tmp/environment.env"); err == nil {
		t.Fatal("environment files outside the managed runtime directory must be rejected")
	}
	if err := validateAppManagerEnvFile("/var/lib/serverpilot/appmanager/tmp/../master.key"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}
