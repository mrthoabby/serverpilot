package replicas

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidateCreate(t *testing.T) {
	valid := CreateRequest{
		ParentID:     "abcdef123456",
		Name:         "app-replica-1",
		Alias:        "go-up",
		TemplateType: "api",
		Env:          []string{"PORT=8080", "TOKEN=secret"},
	}
	if err := validateCreate(valid); err != nil {
		t.Fatalf("validateCreate(valid) = %v", err)
	}

	invalid := valid
	invalid.Name = "../bad"
	if err := validateCreate(invalid); err == nil {
		t.Fatal("validateCreate accepted invalid name")
	}

	invalid = valid
	invalid.Env = []string{"BAD-NAME=value"}
	if err := validateCreate(invalid); err == nil {
		t.Fatal("validateCreate accepted invalid env key")
	}
}

func TestCountReplicasLimit(t *testing.T) {
	reg := &registry{Replicas: []Replica{
		{ParentID: "p1", ParentName: "app", Name: "app-a"},
		{ParentID: "p1", ParentName: "app", Name: "app-b"},
		{ParentID: "p1", ParentName: "app", Name: "app-c"},
		{ParentID: "p2", ParentName: "other", Name: "other-a"},
	}}
	if got := countReplicas(reg, "p1", "app"); got != maxReplicas {
		t.Fatalf("countReplicas = %d, want %d", got, maxReplicas)
	}
}

func TestFingerprintChangesWithRelevantConfig(t *testing.T) {
	base := inspectData{}
	base.Config.Image = "app:v1"
	base.Config.Env = []string{"B=2", "A=1"}
	base.Config.Cmd = []string{"serve"}
	base.Config.ExposedPorts = map[string]any{"8080/tcp": nil}
	base.HostConfig.RestartPolicy.Name = "always"

	fp1, err := Fingerprint(base)
	if err != nil {
		t.Fatalf("Fingerprint(base): %v", err)
	}

	same := base
	same.Config.Env = []string{"A=1", "B=2"}
	fpSame, err := Fingerprint(same)
	if err != nil {
		t.Fatalf("Fingerprint(same): %v", err)
	}
	if fp1 != fpSame {
		t.Fatal("fingerprint changed only because env order changed")
	}

	changed := base
	changed.Config.Image = "app:v2"
	fp2, err := Fingerprint(changed)
	if err != nil {
		t.Fatalf("Fingerprint(changed): %v", err)
	}
	if fp1 == fp2 {
		t.Fatal("fingerprint did not change when image changed")
	}
}

func TestBuildRunArgs(t *testing.T) {
	parent := inspectData{}
	parent.Config.User = "1000:1000"
	parent.Config.WorkingDir = "/app"
	parent.Config.Entrypoint = []string{"/entrypoint"}
	parent.Config.Cmd = []string{"serve"}
	parent.HostConfig.RestartPolicy.Name = "always"

	args := BuildRunArgs(parent, "app-replica", "snapshot:latest", []string{"PORT=8080"}, 3001, "8080", []CopiedMount{
		{CopyPath: "/opt/app/replicas/app-replica/mounts/m00", Destination: "/data", ReadWrite: true},
	})
	want := []string{
		"run", "-d", "--name", "app-replica",
		"--user", "1000:1000",
		"--workdir", "/app",
		"--restart", "always",
		"-e", "PORT=8080",
		"-p", "127.0.0.1:3001:8080",
		"-v", "/opt/app/replicas/app-replica/mounts/m00:/data:rw",
		"--entrypoint", "/entrypoint",
		"snapshot:latest",
		"serve",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("BuildRunArgs mismatch\n got: %#v\nwant: %#v", args, want)
	}
}

func TestCopyPathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := copyPath(link, filepath.Join(dir, "copy")); err == nil {
		t.Fatal("copyPath accepted symlink source")
	}
}

func TestProxyPassPortMatchingIsExact(t *testing.T) {
	if !proxyPassMatchesPort("http://127.0.0.1:3000", 3000) {
		t.Fatal("expected exact port match")
	}
	if proxyPassMatchesPort("http://127.0.0.1:30001", 3000) {
		t.Fatal("matched partial port")
	}
	updated := replaceProxyPort("proxy_pass http://localhost:3000;\nproxy_pass http://127.0.0.1:3000/api;", 3000, 3002)
	if updated != "proxy_pass http://localhost:3002;\nproxy_pass http://127.0.0.1:3002/api;" {
		t.Fatalf("replaceProxyPort = %q", updated)
	}
}
