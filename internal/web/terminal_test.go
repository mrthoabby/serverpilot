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
