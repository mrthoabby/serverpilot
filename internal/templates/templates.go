package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/mrthoabby/serverpilot/internal/nginx"
)

// TemplateType represents the type of nginx configuration template.
type TemplateType string

const (
	// NestJS is a reverse proxy template with WebSocket support.
	NestJS TemplateType = "nestjs"
	// API is a standard reverse proxy template with rate limiting headers.
	API TemplateType = "api"
)

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// TemplateData holds the data used to render nginx config templates.
type TemplateData struct {
	Domain string
	Port   int
}

const nestjsTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    location / {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }
}
`

const apiTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    location / {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-RateLimit-Limit "100";
        proxy_set_header X-RateLimit-Remaining "";
        proxy_read_timeout 30;
        proxy_connect_timeout 10;
    }
}
`

// GetTemplate returns the rendered nginx config string for the given template type.
func GetTemplate(templateType TemplateType, domain string, port int) (string, error) {
	if !isValidDomain(domain) {
		return "", fmt.Errorf("invalid domain format: only alphanumeric characters, dots, and hyphens are allowed")
	}

	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port number: %d", port)
	}

	var tmplStr string
	switch templateType {
	case NestJS:
		tmplStr = nestjsTemplate
	case API:
		tmplStr = apiTemplate
	default:
		return "", fmt.Errorf("unknown template type: %s", string(templateType))
	}

	tmpl, err := template.New("nginx").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	data := TemplateData{
		Domain: domain,
		Port:   port,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// ApplyTemplate generates an nginx config from a template, writes it to sites-available,
// enables the site, and reloads nginx.
func ApplyTemplate(templateType TemplateType, domain string, containerPort int) error {
	config, err := GetTemplate(templateType, domain, containerPort)
	if err != nil {
		return err
	}

	configPath := filepath.Join("/etc/nginx/sites-available", domain)

	// Validate the path is within the nginx directory.
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}
	if !strings.HasPrefix(absPath, "/etc/nginx/") {
		return fmt.Errorf("config path is outside nginx directory")
	}

	if err := os.WriteFile(absPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := nginx.EnableSite(domain); err != nil {
		return fmt.Errorf("failed to enable site: %w", err)
	}

	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}
