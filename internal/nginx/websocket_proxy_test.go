package nginx

import (
	"strings"
	"testing"
)

func TestPatchWebSocketProxyDirectives(t *testing.T) {
	before := `server {
    listen 443 ssl;
    server_name pilot.example.com;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
    }
}
`
	after, changed := patchWebSocketProxyDirectives(before, 8090)
	if !changed {
		t.Fatal("expected patch to apply")
	}
	for _, want := range []string{
		"proxy_set_header Upgrade",
		"proxy_set_header Connection",
		"proxy_http_version 1.1",
		"proxy_read_timeout 86400",
	} {
		if !strings.Contains(after, want) {
			t.Fatalf("patched config missing %q:\n%s", want, after)
		}
	}
}

func TestPatchWebSocketProxyDirectivesNoOpWhenPresent(t *testing.T) {
	config := `location / {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Upgrade $http_upgrade;
}
`
	_, changed := patchWebSocketProxyDirectives(config, 8090)
	if changed {
		t.Fatal("expected no change when Upgrade already present")
	}
}
