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
	// NextJS is an optimized reverse proxy for Next.js apps (SSR, ISR, static assets, image optimization).
	NextJS TemplateType = "nextjs"
	// Frontend is a static file / SPA template (React, Vue, Angular, etc.) served directly by Nginx.
	Frontend TemplateType = "frontend"
	// MinIO is an object-storage reverse proxy template.
	// Disables body-size limits and nginx buffering — both are critical for
	// large-file uploads and the MinIO SDK chunked-upload protocol.
	MinIO TemplateType = "minio"
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

const nextjsTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Next.js static assets — long cache, immutable
    location /_next/static/ {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_cache_valid 200 365d;
        add_header Cache-Control "public, max-age=31536000, immutable";
        access_log off;
    }

    # Next.js image optimization
    location /_next/image {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60;
    }

    # Public static files
    location /public/ {
        proxy_pass http://127.0.0.1:{{.Port}};
        add_header Cache-Control "public, max-age=86400";
        access_log off;
    }

    # Next.js data routes (ISR / SSR JSON payloads)
    location /_next/data/ {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API routes
    location /api/ {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30;
    }

    # Main — SSR pages, WebSocket for HMR in dev
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
        proxy_buffering off;
    }
}
`

const frontendTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

    # All requests proxy to the frontend dev server / container
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
        proxy_buffering off;
    }

    # Static assets — cache aggressively
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$ {
        proxy_pass http://127.0.0.1:{{.Port}};
        add_header Cache-Control "public, max-age=2592000";
        access_log off;
    }
}
`

// minioTemplate is an nginx reverse-proxy config tuned for MinIO object storage.
// Key differences from a standard API config:
//   - client_max_body_size 0  — no upload size cap; MinIO handles multi-GB objects.
//   - proxy_request_buffering off  — nginx must not buffer the upload body in RAM/disk
//     before forwarding; without this, PUT/POST uploads to MinIO break or time out.
//   - proxy_buffering off  — disables response buffering so downloads stream directly.
//   - proxy_http_version 1.1 + Connection ""  — enables keep-alive; the MinIO SDK
//     uses persistent connections for chunked uploads (AWS Signature V4 streaming).
//   - 300s timeouts  — generous for slow uploads and large object transfers.
//
// SSL: this is the HTTP-only base config. Run certbot after creating the site
// to add the SSL block and redirect (same pattern as all other templates).
const minioTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    # No upload-size limit — MinIO handles multi-gigabyte objects.
    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:{{.Port}};

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Critical for MinIO — nginx must not buffer the request body.
        # Buffering causes PUT/multipart uploads to fail or stall.
        proxy_request_buffering  off;
        proxy_buffering          off;

        # HTTP/1.1 keep-alive (required for MinIO SDK chunked / AWS-streaming uploads).
        proxy_http_version 1.1;
        proxy_set_header   Connection "";

        # Generous timeouts for slow connections and large object transfers.
        proxy_connect_timeout 300;
        proxy_send_timeout    300;
        proxy_read_timeout    300;
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
	case NextJS:
		tmplStr = nextjsTemplate
	case Frontend:
		tmplStr = frontendTemplate
	case MinIO:
		tmplStr = minioTemplate
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
