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
	nginxBaseDir      = "/etc/nginx"
)

const securityCatchAllName = "00-serverpilot-unmatched-hosts"

const securityCatchAllHTTPOnlyConfig = `# Managed by ServerPilot. Catches HTTP requests for hosts that do not
# match an explicit nginx site, so they never fall through to the dashboard.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    default_type text/plain;
    return 404 "Site not found\n";
}
`

const securityCatchAllTLSConfig = securityCatchAllHTTPOnlyConfig + `
# Reject unknown HTTPS hosts during TLS negotiation when supported by nginx.
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
`

// Site represents an Nginx site configuration.
type Site struct {
	Domain      string   `json:"domain"`
	ServerNames []string `json:"server_names,omitempty"`
	ConfigPath  string   `json:"config_path"`
	ListenPort  string   `json:"listen_port"`
	ProxyPass   string   `json:"proxy_pass"`
	SSLEnabled  bool     `json:"ssl_enabled"`
	SSLAutoRnw  bool     `json:"ssl_auto_renew"`
	WWWEnabled  bool     `json:"www_enabled"`
	Enabled     bool     `json:"enabled"`
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
			names := parseServerNames(line)
			site.ServerNames = appendUniqueServerNames(site.ServerNames, names...)
			if site.Domain == "" {
				site.Domain = primaryServerName(names)
			}
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

	if site.Domain == "" {
		site.Domain = primaryServerName(site.ServerNames)
	}
	site.WWWEnabled = hasWWWAlias(site.Domain, site.ServerNames)

	return site, nil
}

func parseServerNames(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "server_name ") {
		return nil
	}
	raw := strings.TrimSpace(strings.TrimPrefix(line, "server_name "))
	if idx := strings.Index(raw, ";"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.Fields(raw)
}

func appendUniqueServerNames(existing []string, names ...string) []string {
	seen := make(map[string]bool, len(existing)+len(names))
	for _, name := range existing {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range names {
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		existing = append(existing, name)
		seen[key] = true
	}
	return existing
}

func primaryServerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	for _, name := range names {
		if name != "_" && !strings.HasPrefix(strings.ToLower(name), "www.") {
			return name
		}
	}
	return names[0]
}

func hasWWWAlias(domain string, names []string) bool {
	alias, err := WWWAliasForDomain(domain)
	if err != nil {
		return false
	}
	seenDomain := false
	seenAlias := false
	for _, name := range names {
		switch strings.ToLower(name) {
		case strings.ToLower(domain):
			seenDomain = true
		case strings.ToLower(alias):
			seenAlias = true
		}
	}
	return seenDomain && seenAlias
}

// WWWAliasForDomain returns the www host for a primary domain.
func WWWAliasForDomain(domain string) (string, error) {
	if !isValidDomain(domain) {
		return "", fmt.Errorf("invalid domain format")
	}
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		return "", fmt.Errorf("domain already starts with www")
	}
	return "www." + domain, nil
}

// AddWWWAliasToConfig adds www.<domain> to every server_name directive that
// names domain. It preserves the rest of the config and reports whether it
// changed anything.
func AddWWWAliasToConfig(content, domain string) (string, bool, error) {
	alias, err := WWWAliasForDomain(domain)
	if err != nil {
		return "", false, err
	}

	lines := strings.Split(content, "\n")
	foundDomain := false
	changed := false
	for i, line := range lines {
		updated, lineFound, lineChanged := addWWWAliasToServerNameLine(line, domain, alias)
		if lineFound {
			foundDomain = true
		}
		if lineChanged {
			lines[i] = updated
			changed = true
		}
	}
	if !foundDomain {
		return "", false, fmt.Errorf("domain not found in server_name directives")
	}
	return strings.Join(lines, "\n"), changed, nil
}

func addWWWAliasToServerNameLine(line, domain, alias string) (string, bool, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, "server_name ") {
		return line, false, false
	}

	indent := line[:len(line)-len(trimmed)]
	raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "server_name "))
	semiIdx := strings.Index(raw, ";")
	if semiIdx < 0 {
		return line, false, false
	}

	beforeSemi := raw[:semiIdx]
	afterSemi := raw[semiIdx+1:]
	names := strings.Fields(beforeSemi)
	hasDomain := false
	hasAlias := false
	for _, name := range names {
		switch strings.ToLower(name) {
		case strings.ToLower(domain):
			hasDomain = true
		case strings.ToLower(alias):
			hasAlias = true
		}
	}
	if !hasDomain {
		return line, false, false
	}
	if hasAlias {
		return line, true, false
	}

	names = append(names, alias)
	return indent + "server_name " + strings.Join(names, " ") + ";" + afterSemi, true, true
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
		return fmt.Errorf("site config not found")
	}

	// Hardening (CWE-362 / CWE-22): the prior os.Remove + os.Symlink sequence
	// has a TOCTOU window where a local attacker could swap the path between
	// the two calls. We close that window by symlinking to a temp name and
	// then atomically renaming over the target. Also refuse to remove a
	// non-symlink (which would erase a real config file).
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to overwrite non-symlink at sites-enabled path")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat failed")
	}

	tmpLink := enabledPath + ".sp-tmp-link"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(availablePath, tmpLink); err != nil {
		return fmt.Errorf("failed to enable site")
	}
	if err := os.Rename(tmpLink, enabledPath); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("failed to enable site")
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

// SecurityCatchAllEnabled reports whether ServerPilot's unmatched-host guard
// config is installed and enabled in nginx.
func SecurityCatchAllEnabled() bool {
	availablePath := filepath.Join(sitesAvailableDir, securityCatchAllName)
	content, err := os.ReadFile(availablePath)
	if err != nil {
		return false
	}
	if !strings.Contains(string(content), "Managed by ServerPilot") || !strings.Contains(string(content), "Site not found") {
		return false
	}

	enabledPath := filepath.Join(sitesEnabledDir, securityCatchAllName)
	info, err := os.Lstat(enabledPath)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// InstallSecurityCatchAll installs a default_server guard for hosts that do
// not match any explicit nginx server_name. It first tries an HTTP+TLS
// configuration; if the local nginx does not support ssl_reject_handshake or
// already has a TLS default_server, it falls back to HTTP-only.
func InstallSecurityCatchAll() (bool, error) {
	if err := installSecurityCatchAllContent(securityCatchAllTLSConfig); err == nil {
		return true, nil
	}
	if err := installSecurityCatchAllContent(securityCatchAllHTTPOnlyConfig); err != nil {
		return false, err
	}
	return false, nil
}

func installSecurityCatchAllContent(content string) error {
	configPath := filepath.Join(sitesAvailableDir, securityCatchAllName)
	enabledPath := filepath.Join(sitesEnabledDir, securityCatchAllName)
	if !isWithinNginxDir(configPath) || !isWithinNginxDir(enabledPath) {
		return fmt.Errorf("path is outside nginx directory")
	}

	hadOriginal := false
	var original []byte
	if info, err := os.Lstat(configPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
			return fmt.Errorf("refusing to overwrite unsafe catch-all config")
		}
		data, readErr := os.ReadFile(configPath)
		if readErr != nil {
			return fmt.Errorf("failed to read existing catch-all config")
		}
		original = data
		hadOriginal = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect catch-all config")
	}

	hadEnabled := false
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to overwrite non-symlink catch-all enable path")
		}
		hadEnabled = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect catch-all enable path")
	}

	if err := writeConfigAtomic(configPath, []byte(content)); err != nil {
		return err
	}
	if err := enableConfigName(securityCatchAllName); err != nil {
		restoreSecurityCatchAll(configPath, enabledPath, original, hadOriginal, hadEnabled)
		return err
	}
	if err := TestConfig(); err != nil {
		restoreSecurityCatchAll(configPath, enabledPath, original, hadOriginal, hadEnabled)
		return err
	}
	if err := ReloadNginx(); err != nil {
		restoreSecurityCatchAll(configPath, enabledPath, original, hadOriginal, hadEnabled)
		return err
	}
	return nil
}

func restoreSecurityCatchAll(configPath, enabledPath string, original []byte, hadOriginal, hadEnabled bool) {
	if hadOriginal {
		_ = writeConfigAtomic(configPath, original)
	} else {
		_ = os.Remove(configPath)
	}
	if !hadEnabled {
		_ = os.Remove(enabledPath)
	}
}

func writeConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return fmt.Errorf("failed to create temp config")
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp config")
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod temp config")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync temp config")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp config")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to install config")
	}
	cleanup = false
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func enableConfigName(name string) error {
	if !isValidConfigName(name) {
		return fmt.Errorf("invalid config name")
	}
	availablePath := filepath.Join(sitesAvailableDir, name)
	enabledPath := filepath.Join(sitesEnabledDir, name)
	if !isWithinNginxDir(availablePath) || !isWithinNginxDir(enabledPath) {
		return fmt.Errorf("path is outside nginx directory")
	}
	if _, err := os.Stat(availablePath); os.IsNotExist(err) {
		return fmt.Errorf("site config not found")
	}
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to overwrite non-symlink at sites-enabled path")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat failed")
	}

	tmpLink := enabledPath + ".sp-tmp-link"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(availablePath, tmpLink); err != nil {
		return fmt.Errorf("failed to enable config")
	}
	if err := os.Rename(tmpLink, enabledPath); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("failed to enable config")
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
//
// Hardening (CWE-22): the previous version only resolved symlinks on the
// directory portion of the path, which left a hole — the LEAF could be a
// symlink pointing anywhere on disk and pass the check. We now also resolve
// the leaf if it exists. We additionally use filepath.Rel for the prefix
// check, which is robust against trailing-slash and "/etc/nginxFOO" tricks
// that strings.HasPrefix would have allowed.
func isWithinNginxDir(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	clean := filepath.Clean(absPath)

	// If the leaf exists and is a symlink, resolve it. If the leaf doesn't
	// exist yet, only resolve the parent (it must already exist).
	resolved := clean
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if r, err := filepath.EvalSymlinks(clean); err == nil {
				resolved = r
			} else {
				return false
			}
		}
	} else {
		if r, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
			resolved = filepath.Join(r, filepath.Base(clean))
		}
	}

	rel, err := filepath.Rel(nginxBaseDir, resolved)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if strings.HasPrefix(rel, "..") {
		return false
	}
	return true
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

// domainRegex enforces a strict FQDN structure: each label is 1-63 alnum/-,
// labels never start or end with -, at least one dot, no consecutive dots,
// no trailing dot, TLD must be letters-only (2-63). Tightens the previously
// over-permissive `^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$` pattern that
// accepted "a..b", "a-", and other malformed inputs (CWE-20).
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// IsValidDomainExported checks that a domain contains only allowed characters.
// Exported for use by other packages.
func IsValidDomainExported(domain string) bool {
	return isValidDomain(domain)
}

// isValidDomain checks that a domain contains only allowed characters AND
// follows valid FQDN structure.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	return domainRegex.MatchString(domain)
}
