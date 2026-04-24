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
