package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

var dashboardProxyPassPattern = regexp.MustCompile(`^proxy_pass\s+http://(127\.0\.0\.1|localhost):(\d+)/?\s*;`)

// FindDashboardVhostPath locates the nginx vhost file for a dashboard domain.
func FindDashboardVhostPath(domain string, dashboardPort int) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if !IsValidDomainExported(domain) {
		return "", fmt.Errorf("invalid domain")
	}

	direct := filepath.Join(sitesAvailableDir, domain)
	if abs, err := filepath.Abs(direct); err == nil {
		if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
			return abs, nil
		}
	}

	entries, err := os.ReadDir(sitesAvailableDir)
	if err != nil {
		return "", fmt.Errorf("failed to read nginx sites")
	}

	portNeedle := fmt.Sprintf("127.0.0.1:%d", dashboardPort)
	localNeedle := fmt.Sprintf("localhost:%d", dashboardPort)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(sitesAvailableDir, entry.Name())
		abs, err := filepath.Abs(path)
		if err != nil || !isWithinNginxDir(abs) {
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, portNeedle) && !strings.Contains(content, localNeedle) {
			continue
		}
		if configMatchesDomain(content, domain) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("dashboard vhost not found")
}

func configMatchesDomain(content, domain string) bool {
	domain = strings.ToLower(domain)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "server_name ") {
			continue
		}
		for _, name := range parseServerNames(line) {
			if strings.EqualFold(strings.TrimSpace(name), domain) {
				return true
			}
		}
	}
	return false
}

// InspectDashboardWebSocketProxy checks the nginx vhost for dashboard WebSocket headers.
func InspectDashboardWebSocketProxy(domain string, dashboardPort int) (WebSocketProxyStatus, error) {
	if !IsValidDomainExported(domain) {
		return WebSocketProxyStatus{}, fmt.Errorf("invalid domain")
	}
	if dashboardPort < 1 || dashboardPort > 65535 {
		return WebSocketProxyStatus{}, fmt.Errorf("invalid port")
	}

	configPath, err := FindDashboardVhostPath(domain, dashboardPort)
	if err != nil {
		st := WebSocketProxyStatus{
			Missing: []string{"nginx vhost file missing"},
			Message: "No nginx site config found for this dashboard domain",
		}
		return st, nil
	}

	st := WebSocketProxyStatus{ConfigPath: configPath}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return WebSocketProxyStatus{}, fmt.Errorf("failed to read nginx config")
	}
	content := string(data)
	if !configReferencesDashboardPort(content, dashboardPort) {
		st.Missing = append(st.Missing, "proxy_pass to dashboard port")
		st.Message = "Config exists but does not proxy to the dashboard port"
		return st, nil
	}

	missingBlocks := missingWebSocketProxyBlocks(content, dashboardPort)
	if len(missingBlocks) == 0 {
		st.OK = true
		st.Message = "WebSocket proxy headers present"
		return st, nil
	}
	st.Missing = missingBlocks
	st.Message = "Missing WebSocket/SSE proxy headers in nginx"
	return st, nil
}

func configReferencesDashboardPort(content string, dashboardPort int) bool {
	portNeedle := fmt.Sprintf("127.0.0.1:%d", dashboardPort)
	localNeedle := fmt.Sprintf("localhost:%d", dashboardPort)
	return strings.Contains(content, portNeedle) || strings.Contains(content, localNeedle)
}

func missingWebSocketProxyBlocks(content string, dashboardPort int) []string {
	lines := strings.Split(content, "\n")
	var missing []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		m := dashboardProxyPassPattern.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		port, err := strconv.Atoi(m[2])
		if err != nil || port != dashboardPort {
			continue
		}
		absent := locationBlockMissingDirectives(lines, i, wsProxyRequiredDirectives)
		if len(absent) > 0 {
			missing = append(missing, fmt.Sprintf("location block at line %d missing: %s", i+1, strings.Join(absent, ", ")))
		}
	}
	return missing
}

func locationBlockMissingDirectives(lines []string, proxyLineIdx int, directives []string) []string {
	start, end := locationBlockRange(lines, proxyLineIdx)
	if start < 0 || end <= start {
		return directives
	}
	var absent []string
	for _, directive := range directives {
		found := false
		for j := start; j <= end && j < len(lines); j++ {
			if strings.Contains(lines[j], directive) {
				found = true
				break
			}
		}
		if !found {
			absent = append(absent, directive)
		}
	}
	return absent
}

func locationBlockHasUpgrade(lines []string, proxyLineIdx int) bool {
	start, end := locationBlockRange(lines, proxyLineIdx)
	if start < 0 || end <= start {
		return false
	}
	for j := start; j <= end && j < len(lines); j++ {
		if strings.Contains(lines[j], "proxy_set_header Upgrade") {
			return true
		}
	}
	return false
}

func locationBlockRange(lines []string, proxyLineIdx int) (start, end int) {
	start = -1
	for i := proxyLineIdx; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "location ") {
			start = i
			break
		}
	}
	if start < 0 {
		return -1, -1
	}
	depth := 0
	for j := start; j < len(lines); j++ {
		depth += strings.Count(lines[j], "{")
		depth -= strings.Count(lines[j], "}")
		if depth == 0 && j > start {
			return start, j
		}
	}
	return start, len(lines) - 1
}

func locationBlockText(lines []string, proxyLineIdx int) string {
	start, end := locationBlockRange(lines, proxyLineIdx)
	if start < 0 || end < start {
		return ""
	}
	return strings.Join(lines[start:end+1], "\n")
}

func filterMissingProxyDirectives(blockText string, directives []string) []string {
	if blockText == "" {
		return directives
	}
	var out []string
	for _, directive := range directives {
		needle := strings.TrimSpace(directive)
		needle = strings.TrimSuffix(needle, ";")
		if directiveLinePresent(blockText, needle) {
			continue
		}
		out = append(out, directive)
	}
	return out
}

func directiveLinePresent(blockText, needle string) bool {
	if strings.HasPrefix(needle, "proxy_http_version") && strings.Contains(blockText, "proxy_http_version") {
		return true
	}
	for _, line := range strings.Split(blockText, "\n") {
		if strings.TrimSpace(line) == needle {
			return true
		}
	}
	return false
}

func leadingIndent(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 4
			continue
		}
		break
	}
	return n
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
	if configPath == "" {
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
	original := append([]byte(nil), data...)
	patched, changed := patchWebSocketProxyDirectives(string(data), dashboardPort)
	if !changed {
		st, _ = InspectDashboardWebSocketProxy(domain, dashboardPort)
		if !st.OK {
			return st, fmt.Errorf("nginx vhost exists but could not be patched automatically — run: sudo sp expose --domain %s --upgrade", domain)
		}
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
		_ = os.WriteFile(configPath, original, 0o644)
		_ = ReloadNginx()
		return WebSocketProxyStatus{}, fmt.Errorf("nginx reload failed after patch")
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
	lines := strings.Split(content, "\n")
	insertBlock := []string{
		"        proxy_http_version 1.1;",
		"        proxy_set_header Upgrade $http_upgrade;",
		"        proxy_set_header Connection \"upgrade\";",
		"        proxy_cache_bypass $http_upgrade;",
		"        proxy_read_timeout 86400;",
		"        proxy_buffering off;",
		"        proxy_cache off;",
	}

	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		m := dashboardProxyPassPattern.FindStringSubmatch(trimmed)
		if m != nil {
			port, err := strconv.Atoi(m[2])
			if err == nil && port == dashboardPort && !locationBlockHasUpgrade(lines, i) {
				blockText := locationBlockText(lines, i)
				toInsert := filterMissingProxyDirectives(blockText, insertBlock)
				out = append(out, line)
				if len(toInsert) > 0 {
					out = append(out, toInsert...)
					changed = true
				}
				continue
			}
		}
		out = append(out, line)
	}
	if !changed {
		return content, false
	}
	return strings.Join(out, "\n"), true
}
