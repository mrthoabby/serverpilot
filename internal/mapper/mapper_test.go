package mapper

import (
	"testing"

	"github.com/mrthoabby/serverpilot/internal/nginx"
)

func TestExtractPortFromProxyPass(t *testing.T) {
	tests := map[string]string{
		"http://127.0.0.1:3000/":    "3000",
		"http://localhost:8080/api": "8080",
		"http://127.0.0.1:3000":     "3000",
	}
	for in, want := range tests {
		got, err := extractPortFromProxyPass(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestExtractPortFromProxyPassRejectsInvalid(t *testing.T) {
	if _, err := extractPortFromProxyPass("http://127.0.0.1:notaport/"); err == nil {
		t.Fatal("expected error for invalid proxy_pass port")
	}
}

func TestIsDashboardSite(t *testing.T) {
	opts := ComputeOptions{DashboardDomain: "panel.example.com", DashboardPort: 8090}
	dashboardCfg := "# serverpilot_dashboard\nserver { }"
	if !isDashboardSite(nginx.Site{Domain: "other.example.com", ProxyPass: "http://127.0.0.1:8090/"}, dashboardCfg, opts) {
		t.Fatal("expected marker config to be dashboard")
	}
	if !isDashboardSite(nginx.Site{Domain: "panel.example.com", ProxyPass: "http://127.0.0.1:8090/"}, "", opts) {
		t.Fatal("expected configured domain to be dashboard")
	}
	if isDashboardSite(nginx.Site{Domain: "api.example.com", ProxyPass: "http://127.0.0.1:8090/"}, "# serverpilot_site_id abc\n", opts) {
		t.Fatal("expected app site on container port not to be dashboard")
	}
	if isDashboardSite(nginx.Site{Domain: "api.example.com", ProxyPass: "http://127.0.0.1:8090/"}, "", opts) {
		t.Fatal("expected non-dashboard domain on dashboard port without marker not to match")
	}
	legacyCfg := "location / { proxy_pass http://127.0.0.1:8090/; proxy_buffering off; proxy_read_timeout 86400; }"
	if !isDashboardSite(nginx.Site{Domain: "other.example.com", ProxyPass: "http://127.0.0.1:8090/"}, legacyCfg, ComputeOptions{DashboardPort: 8090}) {
		t.Fatal("expected legacy dashboard template match")
	}
}

func TestMatchesProxyPassExactPort(t *testing.T) {
	if !matchesProxyPass("http://127.0.0.1:3000/", "3000") {
		t.Fatal("expected exact port match")
	}
	if matchesProxyPass("http://127.0.0.1:3001/", "3000") {
		t.Fatal("expected port mismatch")
	}
}
