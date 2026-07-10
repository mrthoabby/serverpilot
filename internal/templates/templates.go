package templates

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/mrthoabby/serverpilot/internal/nginx"
)

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// TemplateData holds the data used to render nginx config templates.
type TemplateData struct {
	Domain string
	Port   int
}

type RedirectData struct {
	Domain     string
	TargetBase string
	Code       int
	Delay      int
	HTML       string
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

const redirectTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    # serverpilot_redirect_target {{.TargetBase}}
    return {{.Code}} {{.TargetBase}}$request_uri;
}
`

const delayedRedirectTemplate = `server {
    listen 80;
    server_name {{.Domain}};

    # serverpilot_redirect_target {{.TargetBase}}
    # serverpilot_redirect_delay {{.Delay}}
    default_type text/html;
    return 200 "{{.HTML}}";
}
`

// GetTemplate returns the rendered nginx config string for the given template type.
func GetTemplate(templateType TemplateType, domain string, port int) (string, error) {
	return RenderProxyConfig(RenderSpec{
		Domain:   domain,
		Port:     port,
		Template: templateType,
		Options:  DefaultOptions(templateType),
	})
}

// ApplyTemplate generates an nginx config from a template, writes it to sites-available,
// enables the site, and reloads nginx.
func ApplyTemplate(templateType TemplateType, domain string, containerPort int) error {
	return applyTemplate(templateType, domain, containerPort, false)
}

// ApplyTemplateWithWWW is ApplyTemplate plus a www.<domain> server_name alias.
func ApplyTemplateWithWWW(templateType TemplateType, domain string, containerPort int) error {
	return applyTemplate(templateType, domain, containerPort, true)
}

func applyTemplate(templateType TemplateType, domain string, containerPort int, includeWWW bool) error {
	config, err := GetTemplate(templateType, domain, containerPort)
	if err != nil {
		return err
	}
	if includeWWW {
		config, _, err = nginx.AddWWWAliasToConfig(config, domain)
		if err != nil {
			return err
		}
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

	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("site already exists")
		}
		return fmt.Errorf("failed to write config: %w", err)
	}
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		_ = os.Remove(absPath)
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(absPath)
		return fmt.Errorf("failed to close config: %w", err)
	}

	if err := nginx.EnableSite(domain); err != nil {
		return fmt.Errorf("failed to enable site: %w", err)
	}

	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

// ApplyRedirectTemplate creates an nginx redirect site and reloads nginx.
func ApplyRedirectTemplate(domain, targetBase string, code int, includeWWW bool, delaySeconds int, message string) error {
	if !isValidDomain(domain) {
		return fmt.Errorf("invalid domain format")
	}
	if targetBase == "" || strings.ContainsAny(targetBase, " \t\r\n;{}") {
		return fmt.Errorf("invalid redirect target")
	}
	if !isValidRedirectTargetBase(targetBase) {
		return fmt.Errorf("invalid redirect target")
	}
	if code != 301 && code != 302 {
		return fmt.Errorf("invalid redirect code")
	}
	if delaySeconds < 0 || delaySeconds > 300 {
		return fmt.Errorf("invalid redirect delay")
	}

	tmplStr := redirectTemplate
	data := RedirectData{Domain: domain, TargetBase: targetBase, Code: code}
	if delaySeconds > 0 {
		data.Delay = delaySeconds
		data.HTML = buildDelayedRedirectHTML(targetBase, delaySeconds, message)
		tmplStr = delayedRedirectTemplate
	}

	tmpl, err := template.New("redirect").Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("failed to parse redirect template: %w", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute redirect template: %w", err)
	}
	config := buf.String()
	if includeWWW {
		config, _, err = nginx.AddWWWAliasToConfig(config, domain)
		if err != nil {
			return err
		}
	}

	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}
	if !strings.HasPrefix(absPath, "/etc/nginx/") {
		return fmt.Errorf("config path is outside nginx directory")
	}
	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("site already exists")
		}
		return fmt.Errorf("failed to write config: %w", err)
	}
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		_ = os.Remove(absPath)
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(absPath)
		return fmt.Errorf("failed to close config: %w", err)
	}

	if err := nginx.EnableSite(domain); err != nil {
		_ = os.Remove(absPath)
		return fmt.Errorf("failed to enable site: %w", err)
	}
	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}
	return nil
}

func isValidRedirectTargetBase(targetBase string) bool {
	u, err := url.Parse(targetBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	if u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return isValidDomain(u.Hostname())
}

func buildDelayedRedirectHTML(targetBase string, delaySeconds int, message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "You are being redirected."
	}
	delay := strconv.Itoa(delaySeconds)
	escapedTarget := html.EscapeString(targetBase + "$request_uri")
	escapedMessage := html.EscapeString(message)
	doc := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="` + delay + `;url=` + escapedTarget + `"><title>Redirecting</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Arial,sans-serif;background:#f6f7f9;color:#14171f}main{max-width:560px;padding:32px;text-align:center}h1{font-size:28px;margin:0 0 12px}p{font-size:16px;line-height:1.5;color:#3e4654}a{color:#0b6bcb}</style></head><body><main><h1>Redirecting</h1><p>` + escapedMessage + `</p><p>Continuing in ` + delay + ` seconds.</p><p><a href="` + escapedTarget + `">Continue now</a></p></main></body></html>`
	return escapeNginxDoubleQuoted(doc)
}

func escapeNginxDoubleQuoted(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}
