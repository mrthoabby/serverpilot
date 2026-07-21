package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatDockerJSONLogLine(t *testing.T) {
	raw := `{"log":"hello\n","stream":"stdout","time":"2026-07-20T12:00:00.000000000Z"}`
	got := formatDockerJSONLogLine(raw)
	want := "2026-07-20T12:00:00.000000000Z hello"
	if got != want {
		t.Fatalf("formatDockerJSONLogLine() = %q, want %q", got, want)
	}
}

func TestReadJSONLogFileTail(t *testing.T) {
	dir := t.TempDir()
	containersDir := filepath.Join(dir, "containers", "abc123")
	if err := os.MkdirAll(containersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(containersDir, "abc123-json.log")
	lines := []string{
		`{"log":"line1\n","stream":"stdout","time":"2026-07-20T12:00:01.000000000Z"}`,
		`{"log":"line2\n","stream":"stdout","time":"2026-07-20T12:00:02.000000000Z"}`,
		`{"log":"line3\n","stream":"stdout","time":"2026-07-20T12:00:03.000000000Z"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readJSONLogFileTail(logPath, 2)
	if err != nil {
		t.Fatalf("readJSONLogFileTail: %v", err)
	}
	if !strings.Contains(got, "line2") || !strings.Contains(got, "line3") {
		t.Fatalf("expected last 2 lines, got:\n%s", got)
	}
	if strings.Contains(got, "line1") {
		t.Fatalf("did not expect line1 in tail output:\n%s", got)
	}
}

func TestSecureDockerLogPathForReadRejectsOutsideLayout(t *testing.T) {
	_, err := secureDockerLogPathForRead("/etc/passwd-json.log")
	if err == nil {
		t.Fatal("expected rejection outside containers layout")
	}
}
