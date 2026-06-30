package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTerminalServiceLogTail(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    int
		wantErr bool
	}{
		{"default", "/api/terminal/service-logs", 120, false},
		{"custom", "/api/terminal/service-logs?tail=50", 50, false},
		{"zero", "/api/terminal/service-logs?tail=0", 0, true},
		{"too-large", "/api/terminal/service-logs?tail=301", 0, true},
		{"non-numeric", "/api/terminal/service-logs?tail=abc", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			got, err := terminalServiceLogTail(req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("tail = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTerminalServiceLogCommandIsFixed(t *testing.T) {
	path, args, display := terminalServiceLogCommand(25)
	if path != "/usr/bin/journalctl" {
		t.Fatalf("path = %q", path)
	}
	got := strings.Join(args, " ")
	want := "-u serverpilot --no-pager --output short-iso --lines 25"
	if got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
	if !strings.Contains(display, "journalctl -u serverpilot") {
		t.Fatalf("display = %q", display)
	}
}

func TestSanitizeDiagnosticLogText(t *testing.T) {
	input := "ok password=hunter2 token=abc123 postgres://user:pass@example/db\nbad\x00line"
	got := sanitizeDiagnosticLogText(input, 2048)
	for _, secret := range []string{"hunter2", "abc123", ":pass@"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitized log still contains %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "password=REDACTED") || !strings.Contains(got, "token=REDACTED") {
		t.Fatalf("sanitized log missing redactions: %q", got)
	}
	if !strings.Contains(got, "bad?line") {
		t.Fatalf("sanitized log did not replace control char: %q", got)
	}
}

func TestTerminalRequestHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://Pilot.Example.com:8443/api/terminal/ws-check", nil)
	if got := terminalRequestHost(req); got != "pilot.example.com" {
		t.Fatalf("host = %q", got)
	}
}

func TestTerminalRequestIsHTTPSFromForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://pilot.example.com/api/terminal/ws-check", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if !terminalRequestIsHTTPS(req) {
		t.Fatal("request should be treated as HTTPS")
	}
}

func TestTerminalHostIsLocal(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "[::1]"} {
		if !terminalHostIsLocal(host) {
			t.Fatalf("%q should be local", host)
		}
	}
	if terminalHostIsLocal("pilot.example.com") {
		t.Fatal("public domain should not be local")
	}
}

func TestTerminalDashboardURL(t *testing.T) {
	if got := terminalDashboardURL("Pilot.Example.com", false); got != "http://pilot.example.com" {
		t.Fatalf("url = %q", got)
	}
	if got := terminalDashboardURL("pilot.example.com", true); got != "https://pilot.example.com" {
		t.Fatalf("url = %q", got)
	}
}

func TestValidSSHPublicKeyPrefix(t *testing.T) {
	valid := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey serverpilot",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfake serverpilot",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY fake",
	}
	for _, key := range valid {
		if !validSSHPublicKeyPrefix(key) {
			t.Fatalf("expected valid SSH public key prefix: %q", key)
		}
	}
	if validSSHPublicKeyPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatal("private key must not be accepted as a public key")
	}
}

func TestTerminalAccessCommands(t *testing.T) {
	if !strings.Contains(terminalInstallCommand, "install.sh") || !strings.Contains(terminalInstallCommand, "sp start -d") {
		t.Fatalf("install command looks wrong: %q", terminalInstallCommand)
	}
	if !strings.Contains(terminalSSHCommandExample, "serverpilot_remote_access_ed25519") {
		t.Fatalf("ssh example looks wrong: %q", terminalSSHCommandExample)
	}
}

func TestTerminalSSHRequestFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ssh/ws?host=89.117.72.100&user=admin&port=2222", nil)
	got, err := terminalSSHRequestFromQuery(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Host != "89.117.72.100" || got.User != "admin" || got.Port != 2222 {
		t.Fatalf("request = %+v", got)
	}
}

func TestTerminalSSHRequestRejectsUnsafeValues(t *testing.T) {
	tests := []string{
		"/api/terminal/ssh/ws?host=-oProxyCommand=sh&user=admin&port=22",
		"/api/terminal/ssh/ws?host=example.com&user=bad%3Buser&port=22",
		"/api/terminal/ssh/ws?host=127.0.0.1&user=admin&port=22",
		"/api/terminal/ssh/ws?host=example.com&user=admin&port=70000",
	}
	for _, target := range tests {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := terminalSSHRequestFromQuery(req); err == nil {
			t.Fatalf("expected %q to be rejected", target)
		}
	}
}

func TestTerminalSSHCommandIsFixed(t *testing.T) {
	req := terminalSSHConnectRequest{Host: "example.com", User: "admin", Port: 22}
	path, args := terminalSSHCommand(req, "/root/.ssh/serverpilot_remote_access_ed25519")
	if path != "/usr/bin/ssh" {
		t.Fatalf("path = %q", path)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-i /root/.ssh/serverpilot_remote_access_ed25519",
		"-o BatchMode=yes",
		"-o PasswordAuthentication=no",
		"-o ClearAllForwardings=yes",
		"-l admin",
		"example.com",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args %q missing %q", joined, want)
		}
	}
}
