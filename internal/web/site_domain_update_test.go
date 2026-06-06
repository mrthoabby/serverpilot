package web

import (
	"testing"

	"github.com/mrthoabby/serverpilot/internal/templates"
)

func TestExtractProxyPassPort(t *testing.T) {
	content, err := templates.GetTemplate(templates.NextJS, "app.example.com", 3000)
	if err != nil {
		t.Fatalf("render template: %v", err)
	}

	port, err := extractProxyPassPort(content)
	if err != nil {
		t.Fatalf("extract port: %v", err)
	}
	if port != 3000 {
		t.Fatalf("port = %d, want 3000", port)
	}
}

func TestExtractProxyPassPortRejectsMissingPort(t *testing.T) {
	if _, err := extractProxyPassPort("server { listen 80; }"); err == nil {
		t.Fatal("expected error for missing proxy_pass port")
	}
}

func TestInferSiteTemplateType(t *testing.T) {
	cases := []struct {
		name string
		tmpl templates.TemplateType
	}{
		{name: "nextjs", tmpl: templates.NextJS},
		{name: "minio", tmpl: templates.MinIO},
		{name: "frontend", tmpl: templates.Frontend},
		{name: "nestjs", tmpl: templates.NestJS},
		{name: "api", tmpl: templates.API},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content, err := templates.GetTemplate(tc.tmpl, tc.name+".example.com", 8080)
			if err != nil {
				t.Fatalf("render template: %v", err)
			}
			got := inferSiteTemplateType(content)
			if got != tc.tmpl {
				t.Fatalf("inferSiteTemplateType() = %q, want %q", got, tc.tmpl)
			}
		})
	}
}

func TestNginxSitePathRejectsTraversal(t *testing.T) {
	badNames := []string{"../evil", "..", "nested/name", `nested\name`, ""}
	for _, name := range badNames {
		t.Run(name, func(t *testing.T) {
			if _, err := nginxSitePath("/etc/nginx/sites-available", name); err == nil {
				t.Fatal("expected path rejection")
			}
		})
	}
}
