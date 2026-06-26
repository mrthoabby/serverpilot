package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WebSocketProxyStatus describes whether the dashboard nginx vhost supports
// terminal WebSocket upgrades.
type WebSocketProxyStatus struct {
	ConfigPath string   `json:"config_path"`
	OK         bool     `json:"ok"`
	Missing    []string `json:"missing,omitempty"`
	Changed    bool     `json:"changed,omitempty"`
	Message    string   `json:"message,omitempty"`
}

var wsProxyRequiredDirectives = []string{
	"proxy_set_header Upgrade",
	"proxy_set_header Connection",
	"proxy_http_version 1.1",
}

// InspectDashboardWebSocketProxy checks the nginx vhost for dashboard WebSocket headers.
func InspectDashboardWebSocketProxy(domain string, dashboardPort int) (WebSocketProxyStatus, error) {
	if !IsValidDomainExported(domain) {
		return WebSocketProxyStatus{}, fmt.Errorf("invalid domain")
	}
	if dashboardPort < 1 || dashboardPort > 65535 {
		return WebSocketProxyStatus{}, fmt.Errorf("invalid port")
	}

	configPath := filepath.Join(sitesAvailableDir, domain)
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("invalid config path")
	}

	st := WebSocketProxyStatus{ConfigPath: absPath}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		st.Missing = append(st.Missing, "nginx vhost file missing")
		st.Message = "No nginx site config found for this dashboard domain"
		return st, nil
	} else if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("failed to read nginx config")
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("failed to read nginx config")
	}
	content := string(data)
	proxyNeedle := fmt.Sprintf("127.0.0.1:%d", dashboardPort)
	if !strings.Contains(content, proxyNeedle) {
		st.Missing = append(st.Missing, "proxy_pass to dashboard port")
		st.Message = "Config exists but does not proxy to the dashboard port"
		return st, nil
	}

	for _, dir := range wsProxyRequiredDirectives {
		if !strings.Contains(content, dir) {
			st.Missing = append(st.Missing, dir)
		}
	}
	if len(st.Missing) == 0 {
		st.OK = true
		st.Message = "WebSocket proxy headers present"
	} else {
		st.Message = "Missing WebSocket/SSE proxy headers in nginx"
	}
	return st, nil
}

// EnsureDashboardWebSocketProxy patches the dashboard nginx vhost to add WebSocket
// proxy headers, preserving certbot SSL blocks. Creates the vhost if missing.
func EnsureDashboardWebSocketProxy(domain string, dashboardPort int) (WebSocketProxyStatus, error) {
	st, err := InspectDashboardWebSocketProxy(domain, dashboardPort)
	if err != nil {
		return WebSocketProxyStatus{}, err
	}
	if st.OK {
		st.Changed = false
		return st, nil
	}

	configPath := st.ConfigPath
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := ApplyServerPilotSite(domain, dashboardPort, false); err != nil {
			return WebSocketProxyStatus{}, err
		}
		st, err = InspectDashboardWebSocketProxy(domain, dashboardPort)
		if err != nil {
			return WebSocketProxyStatus{}, err
		}
		st.Changed = true
		st.Message = "Created dashboard nginx vhost with WebSocket support"
		return st, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("failed to read nginx config")
	}
	patched, changed := patchWebSocketProxyDirectives(string(data), dashboardPort)
	if !changed {
		st, _ = InspectDashboardWebSocketProxy(domain, dashboardPort)
		return st, nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".sp-nginx-*")
	if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("failed to write nginx config")
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(patched); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return WebSocketProxyStatus{}, fmt.Errorf("failed to write nginx config")
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return WebSocketProxyStatus{}, fmt.Errorf("failed to write nginx config")
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		_ = os.Remove(tmpName)
		return WebSocketProxyStatus{}, fmt.Errorf("failed to update nginx config")
	}

	if err := ReloadNginx(); err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("nginx reload failed: %w", err)
	}

	st, err = InspectDashboardWebSocketProxy(domain, dashboardPort)
	if err != nil {
		return WebSocketProxyStatus{}, err
	}
	st.Changed = true
	st.Message = "Patched nginx WebSocket proxy headers and reloaded"
	return st, nil
}

func patchWebSocketProxyDirectives(content string, dashboardPort int) (string, bool) {
	if strings.Contains(content, "proxy_set_header Upgrade") {
		return content, false
	}
	proxyLine := fmt.Sprintf("proxy_pass http://127.0.0.1:%d;", dashboardPort)
	if !strings.Contains(content, proxyLine) {
		// Trailing-slash variant.
		proxyLine = fmt.Sprintf("proxy_pass http://127.0.0.1:%d/;", dashboardPort)
		if !strings.Contains(content, proxyLine) {
			return content, false
		}
	}

	insertBlock := []string{
		"        proxy_http_version 1.1;",
		"        proxy_set_header Upgrade $http_upgrade;",
		"        proxy_set_header Connection \"upgrade\";",
		"        proxy_cache_bypass $http_upgrade;",
		"        proxy_read_timeout 86400;",
		"        proxy_buffering off;",
		"        proxy_cache off;",
	}

	lines := strings.Split(content, "\n")
	var out []string
	changed := false
	for _, line := range lines {
		out = append(out, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == strings.TrimSpace(proxyLine) {
			out = append(out, insertBlock...)
			changed = true
		}
	}
	if !changed {
		return content, false
	}
	return strings.Join(out, "\n"), true
}
