package nginx

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

const (
	sitesAvailableDir = "/etc/nginx/sites-available"
	sitesEnabledDir   = "/etc/nginx/sites-enabled"
	nginxBaseDir       = "/etc/nginx"
)

// Site represents an Nginx site configuration.
type Site struct {
	Domain     string `json:"domain"`
	ConfigPath string `json:"config_path"`
	ListenPort string `json:"listen_port"`
	ProxyPass  string `json:"proxy_pass"`
	SSLEnabled bool   `json:"ssl_enabled"`
	SSLAutoRnw bool   `json:"ssl_auto_renew"`
	Enabled    bool   `json:"enabled"`
}

// ListSites returns all nginx sites from sites-available, indicating whether they are enabled.
func ListSites() ([]Site, error) {
	entries, err := os.ReadDir(sitesAvailableDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read sites-available: %w", err)
	}

	var sites []Site
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		configPath := filepath.Join(sitesAvailableDir, entry.Name())
		if !isWithinNginxDir(configPath) {
			continue
		}

		site, err := ParseConfig(configPath)
		if err != nil {
			continue // skip unparseable configs
		}

		// Check if enabled (symlink exists in sites-enabled).
		enabledPath := filepath.Join(sitesEnabledDir, entry.Name())
		if _, err := os.Lstat(enabledPath); err == nil {
			site.Enabled = true
		}

		sites = append(sites, *site)
	}

	return sites, nil
}

// ParseConfig reads an nginx config file and extracts key directives.
func ParseConfig(path string) (*Site, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	if !isWithinNginxDir(absPath) {
		return nil, fmt.Errorf("path is outside nginx directory")
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config: %w", err)
	}
	defer file.Close()

	site := &Site{
		ConfigPath: absPath,
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "server_name ") {
			domain := strings.TrimSuffix(strings.TrimPrefix(line, "server_name "), ";")
			site.Domain = strings.TrimSpace(domain)
		}

		if strings.HasPrefix(line, "listen ") {
			listen := strings.TrimSuffix(strings.TrimPrefix(line, "listen "), ";")
			listen = strings.TrimSpace(listen)
			// Remove extra directives like "ssl" or "default_server".
			parts := strings.Fields(listen)
			if len(parts) > 0 {
				site.ListenPort = parts[0]
			}
			if strings.Contains(line, "ssl") {
				site.SSLEnabled = true
			}
		}

		if strings.HasPrefix(line, "proxy_pass ") {
			proxyPass := strings.TrimSuffix(strings.TrimPrefix(line, "proxy_pass "), ";")
			site.ProxyPass = strings.TrimSpace(proxyPass)
		}

		if strings.HasPrefix(line, "ssl_certificate ") {
			site.SSLEnabled = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	return site, nil
}

// EnableSite creates a symlink in sites-enabled for the given domain.
func EnableSite(domain string) error {
	if !isValidDomain(domain) {
		return fmt.Errorf("invalid domain format")
	}

	availablePath := filepath.Join(sitesAvailableDir, domain)
	enabledPath := filepath.Join(sitesEnabledDir, domain)

	if !isWithinNginxDir(availablePath) || !isWithinNginxDir(enabledPath) {
		return fmt.Errorf("path is outside nginx directory")
	}

	if _, err := os.Stat(availablePath); os.IsNotExist(err) {
		return fmt.Errorf("site config not found: %s", domain)
	}

	// Remove existing symlink if present.
	os.Remove(enabledPath)

	if err := os.Symlink(availablePath, enabledPath); err != nil {
		return fmt.Errorf("failed to enable site: %w", err)
	}

	return nil
}

// DisableSite removes the symlink from sites-enabled for the given domain.
func DisableSite(domain string) error {
	if !isValidDomain(domain) {
		return fmt.Errorf("invalid domain format")
	}

	enabledPath := filepath.Join(sitesEnabledDir, domain)
	if !isWithinNginxDir(enabledPath) {
		return fmt.Errorf("path is outside nginx directory")
	}

	info, err := os.Lstat(enabledPath)
	if err != nil {
		return fmt.Errorf("site is not enabled: %s", domain)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to remove non-symlink file")
	}

	if err := os.Remove(enabledPath); err != nil {
		return fmt.Errorf("failed to disable site: %w", err)
	}

	return nil
}

// ReloadNginx tests the config and reloads nginx.
func ReloadNginx() error {
	if err := TestConfig(); err != nil {
		return err
	}

	cmd := exec.Command("/usr/bin/systemctl", "reload", "nginx")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload nginx: %s", string(output))
	}

	return nil
}

// TestConfig runs nginx -t to validate the configuration.
func TestConfig() error {
	nginxBin, err := deps.NginxPath()
	if err != nil {
		return err
	}

	cmd := exec.Command(nginxBin, "-t")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}

	return nil
}

// isWithinNginxDir validates that a path is within /etc/nginx/.
func isWithinNginxDir(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Resolve symlinks for the check.
	resolved, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		// If the directory doesn't exist yet, fall back to the raw absolute path.
		return strings.HasPrefix(absPath, nginxBaseDir+"/") || absPath == nginxBaseDir
	}
	return strings.HasPrefix(resolved, nginxBaseDir)
}

// isValidConfigName checks that a config file name is safe (no path traversal, no slashes).
func isValidConfigName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	// Block path traversal and special names.
	if name == "." || name == ".." || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "\x00") {
		return false
	}
	// Allow alphanumeric, dots, hyphens, underscores, tildes.
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// ReadConfigContent returns the raw content of the nginx config file for a given domain/filename.
func ReadConfigContent(name string) (string, error) {
	if !isValidConfigName(name) {
		return "", fmt.Errorf("invalid config name")
	}

	configPath := filepath.Join(sitesAvailableDir, name)
	if !isWithinNginxDir(configPath) {
		return "", fmt.Errorf("path is outside nginx directory")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	return string(data), nil
}

// WriteConfigContent writes new content to the nginx config file for a given domain/filename.
// If validate is true, it writes to a temp file first, runs nginx -t to validate, and
// only copies to the real path if valid. Always cleans up temp files.
// Returns the nginx -t output (if any) and an error.
func WriteConfigContent(name string, content string, validate bool) (string, error) {
	if !isValidConfigName(name) {
		return "", fmt.Errorf("invalid config name")
	}

	configPath := filepath.Join(sitesAvailableDir, name)
	if !isWithinNginxDir(configPath) {
		return "", fmt.Errorf("path is outside nginx directory")
	}

	// Check config file exists first.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", fmt.Errorf("config file not found: %s", name)
	}

	if validate {
		// Write to a temp file, test the whole nginx config with the temp file in place.
		tmpPath := configPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
			return "", fmt.Errorf("failed to write temp config: %w", err)
		}
		// Swap: backup original → put temp as real → test → restore or keep.
		backupPath := configPath + ".bak"
		origData, err := os.ReadFile(configPath)
		if err != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("failed to read original config: %w", err)
		}
		if err := os.WriteFile(backupPath, origData, 0644); err != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("failed to create backup: %w", err)
		}
		// Put new content in place for nginx -t.
		if err := os.Rename(tmpPath, configPath); err != nil {
			os.Remove(tmpPath)
			os.Remove(backupPath)
			return "", fmt.Errorf("failed to swap config: %w", err)
		}
		// Run nginx -t.
		testErr := TestConfig()
		if testErr != nil {
			// Restore the original.
			os.Rename(backupPath, configPath)
			return testErr.Error(), fmt.Errorf("nginx config validation failed")
		}
		// Validation passed — remove backup.
		os.Remove(backupPath)
		return "", nil
	}

	// No validation: just write directly.
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	return "", nil
}

// ServerPilotTemplate generates an nginx reverse proxy config for the ServerPilot dashboard.
// Used by both the CLI setup flow and the web settings handler.
func ServerPilotTemplate(domain string, port int) string {
	return fmt.Sprintf(`server {
    listen 80;
    server_name %s;

    # Note: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and
    # Permissions-Policy are set by the Go SecurityMiddleware to avoid
    # duplicate headers when behind Cloudflare or other reverse proxies.

    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 10;

        # SSE streaming support (for progress modals)
        proxy_buffering off;
        proxy_cache off;
    }
}
`, domain, port)
}

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// IsValidDomainExported checks that a domain contains only allowed characters.
// Exported for use by other packages.
func IsValidDomainExported(domain string) bool {
	return isValidDomain(domain)
}

// isValidDomain checks that a domain contains only allowed characters.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}
