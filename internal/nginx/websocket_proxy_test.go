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

func TestPatchWebSocketProxyDirectivesPatches443Only(t *testing.T) {
	config := `server {
    listen 80;
    server_name pilot.example.com;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
server {
    listen 443 ssl;
    server_name pilot.example.com;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
    }
}
`
	after, changed := patchWebSocketProxyDirectives(config, 8090)
	if !changed {
		t.Fatal("expected patch to apply to 443 block")
	}
	if strings.Count(after, "proxy_set_header Upgrade") != 2 {
		t.Fatalf("expected Upgrade in both blocks, got:\n%s", after)
	}
}

func TestMissingWebSocketProxyBlocks(t *testing.T) {
	config := `server {
    listen 443 ssl;
    location / {
        proxy_pass http://127.0.0.1:8090;
    }
}
`
	missing := missingWebSocketProxyBlocks(config, 8090)
	if len(missing) != 1 {
		t.Fatalf("expected one missing block, got %v", missing)
	}
}

func TestMissingWebSocketProxyBlocksOKWhenPresent(t *testing.T) {
	config := `location / {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_http_version 1.1;
}
`
	if missing := missingWebSocketProxyBlocks(config, 8090); len(missing) != 0 {
		t.Fatalf("expected no missing blocks, got %v", missing)
	}
}

func TestConfigMatchesDomain(t *testing.T) {
	content := "server {\n    server_name pilotsimut.example.com;\n}\n"
	if !configMatchesDomain(content, "pilotsimut.example.com") {
		t.Fatal("expected domain match")
	}
	if configMatchesDomain(content, "other.example.com") {
		t.Fatal("expected no match")
	}
}
