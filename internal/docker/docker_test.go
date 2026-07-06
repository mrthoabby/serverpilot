package docker

import (
	"reflect"
	"testing"
)

func TestBuildRecreateRunArgs(t *testing.T) {
	runtime := containerRuntimeInspect{}
	runtime.Config.User = "1000:1000"
	runtime.Config.WorkingDir = "/app"
	runtime.Config.Labels = map[string]string{"z": "last", "a": "first"}
	runtime.Config.Entrypoint = []string{"/entrypoint"}
	runtime.Config.Cmd = []string{"serve"}
	runtime.HostConfig.RestartPolicy.Name = "on-failure"
	runtime.HostConfig.RestartPolicy.MaximumRetryCount = 3
	runtime.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{
		"8080/tcp": {{HostIP: "127.0.0.1", HostPort: "3001"}},
	}
	runtime.Mounts = []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}{
		{Type: "bind", Source: "/opt/app/data", Destination: "/data", RW: true},
	}

	got := buildRecreateRunArgs(runtime, "app", "sha256:abc", []string{"PORT=8080"})
	want := []string{
		"run", "-d", "--name", "app",
		"--user", "1000:1000",
		"--workdir", "/app",
		"--restart", "on-failure:3",
		"--label", "a=first",
		"--label", "z=last",
		"-e", "PORT=8080",
		"-p", "127.0.0.1:3001:8080/tcp",
		"-v", "/opt/app/data:/data:rw",
		"--entrypoint", "/entrypoint",
		"sha256:abc",
		"serve",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRecreateRunArgs mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildRecreateRunArgsSkipsPublishedPortsForHostNetwork(t *testing.T) {
	runtime := containerRuntimeInspect{}
	runtime.HostConfig.NetworkMode = "host"
	runtime.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{
		"8080/tcp": {{HostPort: "3001"}},
	}

	got := buildRecreateRunArgs(runtime, "app", "app:latest", nil)
	for i, arg := range got {
		if arg == "-p" {
			t.Fatalf("unexpected published port at index %d in %#v", i, got)
		}
	}
}

func TestValidateContainerEnv(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		wantErr bool
	}{
		{name: "valid", env: []string{"PORT=8080", "_TOKEN=abc", "EMPTY="}},
		{name: "missing equals", env: []string{"PORT"}, wantErr: true},
		{name: "empty key", env: []string{"=8080"}, wantErr: true},
		{name: "starts with digit", env: []string{"1PORT=8080"}, wantErr: true},
		{name: "dash", env: []string{"BAD-NAME=8080"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateContainerEnv(tc.env)
			if tc.wantErr && err == nil {
				t.Fatal("validateContainerEnv returned nil error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateContainerEnv returned error: %v", err)
			}
		})
	}
}
