package compose

import (
	"os"
	"strings"
	"testing"
)

func TestWriteDeployEnvIncludesImageRefAndPorts(t *testing.T) {
	dir := t.TempDir()
	path, err := writeDeployEnv(dir, map[string]int{
		"SP_COMPOSE_PORT_APP_8080":   3042,
		"SP_COMPOSE_PORT_MINIO_9000": 3043,
	}, "ghcr.io/org/discovery-central:v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected env path")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "IMAGE_REF=ghcr.io/org/discovery-central:v1.2.3") {
		t.Fatalf("missing IMAGE_REF in env:\n%s", text)
	}
	if !strings.Contains(text, "SP_COMPOSE_PORT_APP_8080=3042") {
		t.Fatalf("missing app port in env:\n%s", text)
	}
	if !strings.Contains(text, "SP_COMPOSE_PORT_MINIO_9000=3043") {
		t.Fatalf("missing minio port in env:\n%s", text)
	}
}

func TestMergePortEnvMapsPreservesStackPorts(t *testing.T) {
	base := endpointPortEnvMap([]Endpoint{
		{Service: "minio", ContainerPort: "9000", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_MINIO_9000", HostPort: 3043},
	})
	overlay := map[string]int{"SP_COMPOSE_PORT_DISCOVERY_CENTRAL_8080": 3042}
	got := mergePortEnvMaps(base, overlay)
	if got["SP_COMPOSE_PORT_MINIO_9000"] != 3043 {
		t.Fatalf("minio port = %d, want 3043", got["SP_COMPOSE_PORT_MINIO_9000"])
	}
	if got["SP_COMPOSE_PORT_DISCOVERY_CENTRAL_8080"] != 3042 {
		t.Fatalf("discovery port = %d, want 3042", got["SP_COMPOSE_PORT_DISCOVERY_CENTRAL_8080"])
	}
}
