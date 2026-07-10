package templates

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RenderSpec is the full input for generating a managed proxy site config.
type RenderSpec struct {
	Domain        string
	Port          int
	Template      TemplateType
	Options       TemplateOptions
	Metadata      SiteMetadata
	IncludeWWW    bool
}

// RenderProxyConfig generates an nginx reverse-proxy config with ServerPilot metadata.
func RenderProxyConfig(spec RenderSpec) (string, error) {
	if !isValidDomain(spec.Domain) {
		return "", fmt.Errorf("invalid domain format")
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return "", fmt.Errorf("invalid port number: %d", spec.Port)
	}
	if !ValidTemplateType(spec.Template) {
		return "", fmt.Errorf("unknown template type: %s", spec.Template)
	}
	opts, err := MergeOptions(spec.Template, spec.Options)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(metadataHeader(spec.Metadata, spec.Template, opts))
	b.WriteString("\n")

	if opts.RateLimitEnabled {
		zone := RateLimitZoneName(spec.Domain)
		b.WriteString(fmt.Sprintf("limit_req_zone $binary_remote_addr zone=%s:10m rate=%s;\n\n", zone, opts.RateLimitRate))
	}

	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString(fmt.Sprintf("    server_name %s;\n\n", spec.Domain))

	if opts.BodySize != "" && opts.BodySize != "1m" {
		b.WriteString(fmt.Sprintf("    client_max_body_size %s;\n\n", opts.BodySize))
	}
	if opts.Gzip {
		b.WriteString(gzipBlock())
	}

	switch spec.Template {
	case NextJS:
		b.WriteString(renderNextJSLocations(spec.Port, opts, spec.Domain))
	case Frontend:
		b.WriteString(renderFrontendLocations(spec.Port, opts, spec.Domain))
	case MinIO:
		b.WriteString(renderMinIOLocation(spec.Port, opts))
	case MCP:
		b.WriteString(renderMCPLocation(spec.Port, opts, spec.Domain))
	default:
		b.WriteString(renderGenericLocation(spec.Port, opts, spec.Domain))
	}

	b.WriteString("}\n")

	config := b.String()
	if spec.IncludeWWW {
		wwwDomain := "www." + spec.Domain
		if !isValidDomain(wwwDomain) {
			return "", fmt.Errorf("invalid www domain")
		}
		wwwSpec := spec
		wwwSpec.Domain = wwwDomain
		wwwSpec.IncludeWWW = false
		wwwCfg, err := RenderProxyConfig(wwwSpec)
		if err != nil {
			return "", err
		}
		config = strings.TrimSpace(config) + "\n\n" + wwwCfg
	}
	return config, nil
}

func metadataHeader(meta SiteMetadata, tmpl TemplateType, opts TemplateOptions) string {
	var lines []string
	if meta.SiteID != "" {
		lines = append(lines, "# serverpilot_site_id "+meta.SiteID)
	}
	if meta.ContainerID != "" {
		lines = append(lines, "# serverpilot_container_id "+meta.ContainerID)
	}
	if meta.ContainerName != "" {
		lines = append(lines, "# serverpilot_container_name "+meta.ContainerName)
	}
	if meta.HostPort > 0 {
		lines = append(lines, "# serverpilot_host_port "+strconv.Itoa(meta.HostPort))
	}
	if meta.ContainerPort > 0 {
		lines = append(lines, "# serverpilot_container_port "+strconv.Itoa(meta.ContainerPort))
	}
	lines = append(lines, "# serverpilot_template "+string(tmpl))
	if data, err := json.Marshal(opts); err == nil {
		lines = append(lines, "# serverpilot_options "+string(data))
	}
	return strings.Join(lines, "\n")
}

func gzipBlock() string {
	return `    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

`
}

func renderGenericLocation(port int, opts TemplateOptions, domain string) string {
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	b.WriteString("    location / {\n")
	b.WriteString(proxyDirectives(upstream, opts, "", domain))
	b.WriteString("    }\n")
	return b.String()
}

func renderMCPLocation(port int, opts TemplateOptions, domain string) string {
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	b.WriteString("    location / {\n")
	b.WriteString(proxyDirectives(upstream, opts, "mcp", domain))
	b.WriteString("    }\n")
	return b.String()
}

func renderMinIOLocation(port int, opts TemplateOptions) string {
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	b.WriteString("    location / {\n")
	b.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstream))
	b.WriteString("        proxy_set_header Host              $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP         $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("        proxy_request_buffering  off;\n")
	b.WriteString("        proxy_buffering          off;\n")
	b.WriteString("        proxy_http_version 1.1;\n")
	b.WriteString("        proxy_set_header   Connection \"\";\n")
	b.WriteString(fmt.Sprintf("        proxy_connect_timeout %d;\n", opts.ProxyConnectTimeout))
	b.WriteString(fmt.Sprintf("        proxy_send_timeout    %d;\n", opts.ProxyReadTimeout))
	b.WriteString(fmt.Sprintf("        proxy_read_timeout    %d;\n", opts.ProxyReadTimeout))
	b.WriteString("    }\n")
	return b.String()
}

func renderFrontendLocations(port int, opts TemplateOptions, domain string) string {
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	b.WriteString("    add_header X-Frame-Options \"SAMEORIGIN\" always;\n")
	b.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	b.WriteString("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n")
	b.WriteString("    location / {\n")
	b.WriteString(proxyDirectives(upstream, opts, "", domain))
	b.WriteString("    }\n\n")
	b.WriteString("    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$ {\n")
	b.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstream))
	b.WriteString("        add_header Cache-Control \"public, max-age=2592000\";\n")
	b.WriteString("        access_log off;\n")
	b.WriteString("    }\n")
	return b.String()
}

func renderNextJSLocations(port int, opts TemplateOptions, domain string) string {
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	b.WriteString("    add_header X-Frame-Options \"SAMEORIGIN\" always;\n")
	b.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	b.WriteString("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n")
	for _, loc := range []struct{ path, extra string }{
		{"/_next/static/", "        proxy_cache_valid 200 365d;\n        add_header Cache-Control \"public, max-age=31536000, immutable\";\n        access_log off;\n"},
		{"/_next/image", ""},
		{"/public/", "        add_header Cache-Control \"public, max-age=86400\";\n        access_log off;\n"},
		{"/_next/data/", ""},
		{"/api/", "        proxy_read_timeout 30;\n"},
		{"/", ""},
	} {
		b.WriteString(fmt.Sprintf("    location %s {\n", loc.path))
		if loc.path == "/" {
			b.WriteString(proxyDirectives(upstream, opts, "", domain))
		} else {
			b.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstream))
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			b.WriteString(loc.extra)
		}
		b.WriteString("    }\n\n")
	}
	return b.String()
}

func proxyDirectives(upstream string, opts TemplateOptions, profile, domain string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstream))
	b.WriteString("        proxy_http_version 1.1;\n")
	if opts.WebSocket {
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
	} else if opts.SSE || profile == "mcp" {
		b.WriteString("        proxy_set_header Connection \"\";\n")
	}
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	if opts.RateLimitEnabled && domain != "" {
		zone := RateLimitZoneName(domain)
		b.WriteString(fmt.Sprintf("        limit_req zone=%s burst=%d nodelay;\n", zone, opts.RateLimitBurst))
	}
	if opts.ResponseBufferingOff || opts.SSE {
		b.WriteString("        proxy_buffering off;\n")
	}
	if opts.RequestBufferingOff {
		b.WriteString("        proxy_request_buffering off;\n")
	}
	if opts.WebSocket {
		b.WriteString("        proxy_cache_bypass $http_upgrade;\n")
	}
	if opts.ProxyReadTimeout > 0 {
		b.WriteString(fmt.Sprintf("        proxy_read_timeout %d;\n", opts.ProxyReadTimeout))
	}
	if opts.ProxyConnectTimeout > 0 {
		b.WriteString(fmt.Sprintf("        proxy_connect_timeout %d;\n", opts.ProxyConnectTimeout))
	}
	return b.String()
}

// ParseMetadataFromConfig extracts ServerPilot metadata comments from nginx config text.
func ParseMetadataFromConfig(content string) SiteMetadata {
	meta := SiteMetadata{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "# serverpilot_site_id "):
			meta.SiteID = strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_site_id "))
		case strings.HasPrefix(line, "# serverpilot_container_id "):
			meta.ContainerID = strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_container_id "))
		case strings.HasPrefix(line, "# serverpilot_container_name "):
			meta.ContainerName = strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_container_name "))
		case strings.HasPrefix(line, "# serverpilot_host_port "):
			if p, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_host_port "))); err == nil {
				meta.HostPort = p
			}
		case strings.HasPrefix(line, "# serverpilot_container_port "):
			if p, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_container_port "))); err == nil {
				meta.ContainerPort = p
			}
		case strings.HasPrefix(line, "# serverpilot_template "):
			meta.Template = strings.TrimSpace(strings.TrimPrefix(line, "# serverpilot_template "))
		}
	}
	return meta
}
