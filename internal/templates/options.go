package templates

import (
	"fmt"
	"regexp"
	"strings"
)

// TemplateType represents the type of nginx configuration template.
type TemplateType string

const (
	NestJS   TemplateType = "nestjs"
	API      TemplateType = "api"
	NextJS   TemplateType = "nextjs"
	Frontend TemplateType = "frontend"
	MinIO    TemplateType = "minio"
	MCP      TemplateType = "mcp"
	GDApp    TemplateType = "gd-app"
)

var validTemplateTypes = map[TemplateType]bool{
	NestJS: true, API: true, NextJS: true, Frontend: true, MinIO: true, MCP: true, GDApp: true,
}

// ValidTemplateType reports whether t is a supported template slug.
func ValidTemplateType(t TemplateType) bool {
	return validTemplateTypes[t]
}

// SiteMetadata is persisted in nginx config comments for managed sites.
type SiteMetadata struct {
	SiteID         string `json:"site_id,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	HostPort       int    `json:"host_port,omitempty"`
	ContainerPort  int    `json:"container_port,omitempty"`
	Template       string `json:"template,omitempty"`
}

// TemplateOptions configures optional nginx proxy behavior.
type TemplateOptions struct {
	WebSocket            bool   `json:"websocket,omitempty"`
	SSE                  bool   `json:"sse,omitempty"`
	BodySize             string `json:"body_size,omitempty"`
	RateLimitEnabled     bool   `json:"rate_limit_enabled,omitempty"`
	RateLimitRate        string `json:"rate_limit_rate,omitempty"`
	RateLimitBurst       int    `json:"rate_limit_burst,omitempty"`
	RequestBufferingOff  bool   `json:"request_buffering_off,omitempty"`
	ResponseBufferingOff bool   `json:"response_buffering_off,omitempty"`
	ProxyReadTimeout     int    `json:"proxy_read_timeout,omitempty"`
	ProxyConnectTimeout  int    `json:"proxy_connect_timeout,omitempty"`
	Gzip                 bool   `json:"gzip,omitempty"`
}

var bodySizeRegex = regexp.MustCompile(`^(0|[1-9][0-9]*[kKmMgG]?)$`)

// DefaultOptions returns template-specific defaults merged with any user overrides.
func DefaultOptions(t TemplateType) TemplateOptions {
	opts := TemplateOptions{
		BodySize:          "1m",
		ProxyReadTimeout:  30,
		ProxyConnectTimeout: 10,
	}
	switch t {
	case NestJS, Frontend:
		opts.WebSocket = true
		opts.ProxyReadTimeout = 86400
		opts.ResponseBufferingOff = true
	case NextJS:
		opts.WebSocket = true
		opts.ProxyReadTimeout = 86400
		opts.ResponseBufferingOff = true
		opts.Gzip = true
	case API:
		opts.RateLimitEnabled = true
		opts.RateLimitRate = "10r/s"
		opts.RateLimitBurst = 20
	case MinIO:
		opts.BodySize = "0"
		opts.RequestBufferingOff = true
		opts.ResponseBufferingOff = true
		opts.ProxyReadTimeout = 300
		opts.ProxyConnectTimeout = 300
	case MCP:
		opts.SSE = true
		opts.ResponseBufferingOff = true
		opts.ProxyReadTimeout = 86400
		opts.BodySize = "50m"
	case GDApp:
		opts.WebSocket = true
		opts.SSE = true
		opts.BodySize = "200m"
		opts.ResponseBufferingOff = true
		opts.ProxyReadTimeout = 86400
		opts.Gzip = true
	}
	return opts
}

// MergeOptions applies user overrides onto defaults for template t.
func MergeOptions(t TemplateType, user TemplateOptions) (TemplateOptions, error) {
	out := DefaultOptions(t)
	if user.WebSocket {
		out.WebSocket = true
	}
	if user.SSE {
		out.SSE = true
	}
	if user.BodySize != "" {
		out.BodySize = user.BodySize
	}
	if user.RateLimitEnabled {
		out.RateLimitEnabled = true
	}
	if user.RateLimitRate != "" {
		out.RateLimitRate = user.RateLimitRate
	}
	if user.RateLimitBurst > 0 {
		out.RateLimitBurst = user.RateLimitBurst
	}
	if user.RequestBufferingOff {
		out.RequestBufferingOff = true
	}
	if user.ResponseBufferingOff {
		out.ResponseBufferingOff = true
	}
	if user.ProxyReadTimeout > 0 {
		out.ProxyReadTimeout = user.ProxyReadTimeout
	}
	if user.ProxyConnectTimeout > 0 {
		out.ProxyConnectTimeout = user.ProxyConnectTimeout
	}
	if user.Gzip {
		out.Gzip = true
	}
	return out, ValidateOptions(out)
}

// ValidateOptions enforces safe ranges for nginx directives.
func ValidateOptions(o TemplateOptions) error {
	if o.BodySize != "" && !bodySizeRegex.MatchString(o.BodySize) {
		return fmt.Errorf("invalid body size")
	}
	if o.RateLimitEnabled {
		if o.RateLimitRate == "" {
			return fmt.Errorf("rate limit rate required when enabled")
		}
		if !regexp.MustCompile(`^[1-9][0-9]*r/[sm]$`).MatchString(o.RateLimitRate) {
			return fmt.Errorf("invalid rate limit rate")
		}
		if o.RateLimitBurst < 1 || o.RateLimitBurst > 10000 {
			return fmt.Errorf("invalid rate limit burst")
		}
	}
	if o.ProxyReadTimeout < 0 || o.ProxyReadTimeout > 86400 {
		return fmt.Errorf("invalid proxy read timeout")
	}
	if o.ProxyConnectTimeout < 0 || o.ProxyConnectTimeout > 3600 {
		return fmt.Errorf("invalid proxy connect timeout")
	}
	return nil
}

// RateLimitZoneName returns a safe nginx zone name derived from domain.
func RateLimitZoneName(domain string) string {
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(domain))
	if len(s) > 40 {
		s = s[:40]
	}
	return "sp_rl_" + s
}
