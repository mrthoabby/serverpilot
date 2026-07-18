package compose

import "testing"

func TestBuildEndpointReconcilePlanPreservesExistingAndChangedPorts(t *testing.T) {
	previous := []Endpoint{
		{Service: "app", ContainerPort: "8080", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_APP_8080", HostPort: 3042},
		{Service: "app", ContainerPort: "8090", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_APP_8090", HostPort: 3043},
	}
	next := []Endpoint{
		{Service: "app", ContainerPort: "8089", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_APP_8089"},
		{Service: "app", ContainerPort: "8090", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_APP_8090"},
		{Service: "minio", ContainerPort: "9000", Protocol: "tcp", EnvVar: "SP_COMPOSE_PORT_MINIO_9000"},
	}

	plan := buildEndpointReconcilePlan(previous, next)

	if plan.Endpoints[0].HostPort != 3042 {
		t.Fatalf("changed REST endpoint host port = %d, want 3042", plan.Endpoints[0].HostPort)
	}
	if plan.Endpoints[1].HostPort != 3043 {
		t.Fatalf("existing MCP endpoint host port = %d, want 3043", plan.Endpoints[1].HostPort)
	}
	if plan.Endpoints[2].HostPort != 0 {
		t.Fatalf("new MinIO endpoint host port = %d, want allocation pending", plan.Endpoints[2].HostPort)
	}
	if len(plan.NewIndexes) != 1 || plan.NewIndexes[0] != 2 {
		t.Fatalf("new endpoint indexes = %v, want [2]", plan.NewIndexes)
	}
	if len(plan.Stale) != 0 {
		t.Fatalf("stale endpoints = %v, want none after REST port transfer", plan.Stale)
	}
}

func TestBuildEndpointReconcilePlanMarksRemovedEndpointStale(t *testing.T) {
	previous := []Endpoint{
		{Service: "app", ContainerPort: "8080", Protocol: "tcp", HostPort: 3042},
		{Service: "admin", ContainerPort: "3000", Protocol: "tcp", HostPort: 3043},
	}
	next := []Endpoint{
		{Service: "app", ContainerPort: "8080", Protocol: "tcp"},
	}

	plan := buildEndpointReconcilePlan(previous, next)

	if len(plan.Stale) != 1 || plan.Stale[0].Service != "admin" {
		t.Fatalf("stale endpoints = %v, want removed admin endpoint", plan.Stale)
	}
}
