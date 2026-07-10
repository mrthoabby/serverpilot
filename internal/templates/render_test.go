package templates

import (
	"strings"
	"testing"
)

func TestRenderProxyConfigIncludesMetadataAndRateLimit(t *testing.T) {
	cfg, err := RenderProxyConfig(RenderSpec{
		Domain:   "api.example.com",
		Port:     3000,
		Template: API,
		Metadata: SiteMetadata{
			SiteID:      "abc123",
			ContainerID: "cid",
			HostPort:    3000,
			Template:    "api",
		},
	})
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(cfg, "# serverpilot_site_id abc123") {
		t.Fatalf("missing site id metadata: %s", cfg)
	}
	if !strings.Contains(cfg, "limit_req_zone") {
		t.Fatalf("expected rate limit zone: %s", cfg)
	}
	if !strings.Contains(cfg, "proxy_pass http://127.0.0.1:3000") {
		t.Fatalf("missing proxy_pass: %s", cfg)
	}
}

func TestRenderProxyConfigMCPIncludesSSE(t *testing.T) {
	cfg, err := RenderProxyConfig(RenderSpec{
		Domain:   "mcp.example.com",
		Port:     3100,
		Template: MCP,
		Metadata: SiteMetadata{SiteID: "m1", Template: "mcp"},
	})
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(cfg, "proxy_buffering off") {
		t.Fatalf("expected buffering off for MCP: %s", cfg)
	}
}

func TestParseMetadataFromConfig(t *testing.T) {
	content := `# serverpilot_site_id deadbeef
# serverpilot_container_id abc
# serverpilot_template mcp
server { listen 80; }`
	meta := ParseMetadataFromConfig(content)
	if meta.SiteID != "deadbeef" || meta.ContainerID != "abc" || meta.Template != "mcp" {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
}
