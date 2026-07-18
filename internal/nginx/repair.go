package nginx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// RepairIssue is a single nginx problem detected before repair.
type RepairIssue struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// RepairReport summarizes nginx diagnosis and automatic fixes.
type RepairReport struct {
	OK             bool          `json:"ok"`
	Issues         []RepairIssue `json:"issues,omitempty"`
	Fixed          []string      `json:"fixed,omitempty"`
	RemovedConfigs []string      `json:"removed_configs,omitempty"`
	RemainingError string        `json:"remaining_error,omitempty"`
}

var nginxTestErrorLine = regexp.MustCompile(`(?m)in (/etc/nginx/[^:]+):(\d+)`)
var serverNamesHashBucketSize = regexp.MustCompile(`(?m)^(\s*)server_names_hash_bucket_size\s+(\d+)\s*;`)
var nginxHTTPBlock = regexp.MustCompile(`(?m)^(\s*http\s*\{)`)

const nginxMainConfigPath = "/etc/nginx/nginx.conf"
const minimumServerNamesHashBucketSize = 128

// Diagnose runs nginx -t and parses common failure patterns.
func Diagnose() RepairReport {
	if err := TestConfig(); err == nil {
		return RepairReport{OK: true}
	} else {
		return RepairReport{
			OK:             false,
			Issues:         parseNginxTestIssues(err.Error()),
			RemainingError: sanitizeNginxError(err.Error()),
		}
	}
}

// Repair fixes known-safe nginx config problems, reloads when clean, and
// returns a structured report for the dashboard.
func Repair() (RepairReport, error) {
	report := Diagnose()
	if report.OK {
		return report, nil
	}
	needsHashRepair := false
	if err := TestConfig(); err != nil {
		needsHashRepair = strings.Contains(err.Error(), "could not build server_names_hash")
	}

	entries, err := os.ReadDir(sitesAvailableDir)
	if err != nil {
		return report, fmt.Errorf("failed to read nginx sites")
	}
	originals := make(map[string]string)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(sitesAvailableDir, entry.Name())
		if !isWithinNginxDir(path) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		patched, changed := dedupeSingletonDirectivesInLocations(string(data))
		if !changed {
			continue
		}
		originals[path] = string(data)
		if err := writeConfigAtomically(path, patched); err != nil {
			if rollbackErr := rollbackSiteConfigs(originals); rollbackErr != nil {
				return report, fmt.Errorf("nginx repair rollback failed")
			}
			return report, err
		}
		report.Fixed = append(report.Fixed, entry.Name()+": removed duplicate proxy directives")
	}

	if needsHashRepair {
		changed, err := repairServerNamesHashBucketSize()
		if err != nil {
			if rollbackErr := rollbackSiteConfigs(originals); rollbackErr != nil {
				return report, fmt.Errorf("nginx repair rollback failed")
			}
			return report, err
		}
		if changed {
			report.Fixed = append(report.Fixed, "nginx.conf: increased server_names_hash_bucket_size to 128")
		}
	}

	report = Diagnose()
	if !report.OK && len(originals) > 0 {
		if err := rollbackSiteConfigs(originals); err != nil {
			return report, fmt.Errorf("nginx repair rollback failed")
		}
		report = Diagnose()
	}
	if report.OK {
		if err := ReloadNginx(); err != nil {
			report.OK = false
			report.RemainingError = "nginx config is valid but reload failed"
			return report, nil
		}
	}
	return report, nil
}

func rollbackSiteConfigs(originals map[string]string) error {
	var errs []error
	for path, original := range originals {
		if err := writeConfigAtomically(path, original); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func repairServerNamesHashBucketSize() (bool, error) {
	data, err := os.ReadFile(nginxMainConfigPath)
	if err != nil {
		return false, fmt.Errorf("failed to read nginx main config")
	}
	patched, changed := ensureServerNamesHashBucketSize(string(data))
	if !changed {
		return false, nil
	}
	info, err := os.Stat(nginxMainConfigPath)
	if err != nil {
		return false, fmt.Errorf("failed to inspect nginx main config")
	}
	tmpPath, err := writeStagedConfig(filepath.Dir(nginxMainConfigPath), patched, info.Mode().Perm())
	if err != nil {
		return false, fmt.Errorf("failed to stage nginx main config")
	}
	defer func() { _ = os.Remove(tmpPath) }()
	if err := testConfigWithPath(tmpPath); err != nil {
		return false, fmt.Errorf("nginx main config validation failed")
	}
	if err := os.Rename(tmpPath, nginxMainConfigPath); err != nil {
		return false, fmt.Errorf("failed to update nginx main config")
	}
	if err := syncDirectory(filepath.Dir(nginxMainConfigPath)); err != nil {
		return false, fmt.Errorf("failed to persist nginx main config")
	}
	return true, nil
}

func ensureServerNamesHashBucketSize(content string) (string, bool) {
	if match := serverNamesHashBucketSize.FindStringSubmatch(content); len(match) == 3 {
		current, err := strconv.Atoi(match[2])
		if err != nil || current >= minimumServerNamesHashBucketSize {
			return content, false
		}
		replacement := match[1] + "server_names_hash_bucket_size 128;"
		return serverNamesHashBucketSize.ReplaceAllString(content, replacement), true
	}
	location := nginxHTTPBlock.FindStringIndex(content)
	if location == nil {
		return content, false
	}
	insert := "\n    server_names_hash_bucket_size 128;"
	return content[:location[1]] + insert + content[location[1]:], true
}

// RemoveSiteFiles deletes a site config from sites-enabled and sites-available.
// Missing paths are ignored. Refuses to remove non-symlink entries in
// sites-enabled unless they are regular files (certbot-style).
func RemoveSiteFiles(configName string) error {
	if !IsValidDomainExported(configName) && configName != "_" && !isValidConfigFileName(configName) {
		return fmt.Errorf("invalid config name")
	}

	enabledPath := filepath.Join(sitesEnabledDir, configName)
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().IsRegular() {
			if err := os.Remove(enabledPath); err != nil {
				return fmt.Errorf("failed to remove enabled site")
			}
		} else {
			return fmt.Errorf("refusing to remove non-file entry from sites-enabled")
		}
	}

	availablePath := filepath.Join(sitesAvailableDir, configName)
	if _, err := os.Stat(availablePath); err == nil {
		if err := os.Remove(availablePath); err != nil {
			return fmt.Errorf("failed to remove site config")
		}
	}
	return nil
}

// SiteConfigExists reports whether sites-available/<name> exists.
func SiteConfigExists(configName string) bool {
	if !IsValidDomainExported(configName) && configName != "_" && !isValidConfigFileName(configName) {
		return false
	}
	path := filepath.Join(sitesAvailableDir, configName)
	info, err := os.Lstat(path)
	return err == nil && !info.IsDir()
}

// ListHiddenSiteConfigs returns config filenames present on disk that the
// dashboard cannot parse into a site row (broken or non-standard files).
func ListHiddenSiteConfigs() ([]string, error) {
	entries, err := os.ReadDir(sitesAvailableDir)
	if err != nil {
		return nil, err
	}
	var hidden []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == securityCatchAllName {
			continue
		}
		path := filepath.Join(sitesAvailableDir, name)
		if !isWithinNginxDir(path) {
			continue
		}
		if _, err := ParseConfig(path); err != nil {
			hidden = append(hidden, name)
		}
	}
	return hidden, nil
}

func isValidConfigFileName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func parseNginxTestIssues(output string) []RepairIssue {
	var issues []RepairIssue
	seen := map[string]bool{}
	for _, match := range nginxTestErrorLine.FindAllStringSubmatch(output, -1) {
		if len(match) < 3 {
			continue
		}
		key := match[1] + ":" + match[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		line := 0
		fmt.Sscanf(match[2], "%d", &line)
		kind := "nginx_config"
		msg := sanitizeNginxError(output)
		if strings.Contains(output, "could not build server_names_hash") {
			kind = "server_names_hash"
			msg = "server name hash bucket is too small"
		} else if strings.Contains(output, "duplicate") {
			kind = "duplicate_directive"
			msg = "duplicate nginx directive"
		}
		issues = append(issues, RepairIssue{
			File:    filepath.Base(match[1]),
			Line:    line,
			Kind:    kind,
			Message: msg,
		})
	}
	if len(issues) == 0 && strings.TrimSpace(output) != "" {
		kind := "nginx_config"
		message := sanitizeNginxError(output)
		if strings.Contains(output, "could not build server_names_hash") {
			kind = "server_names_hash"
			message = "server name hash bucket is too small"
		}
		issues = append(issues, RepairIssue{
			Kind:    kind,
			Message: message,
		})
	}
	return issues
}

func sanitizeNginxError(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return ""
	}
	return "nginx configuration test failed; use server logs for details"
}

func writeConfigAtomically(path, content string) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o640)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmpName, err := writeStagedConfig(dir, content, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpName) }()
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func writeStagedConfig(dir, content string, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, ".sp-repair-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return "", err
	}
	if _, err := tmp.WriteString(content); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

var singletonLocationDirectives = []string{
	"proxy_http_version",
	"proxy_pass",
	"proxy_set_header Upgrade",
	"proxy_set_header Connection",
	"proxy_cache_bypass",
}

func dedupeSingletonDirectivesInLocations(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	var out []string
	changed := false
	inLocation := false
	depth := 0
	seen := map[string]bool{}

	flushLocation := func() {
		inLocation = false
		depth = 0
		seen = map[string]bool{}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "location ") {
			flushLocation()
			inLocation = true
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			out = append(out, line)
			if depth <= 0 {
				depth = 1
			}
			continue
		}

		if inLocation {
			if key := singletonDirectiveKey(trimmed); key != "" {
				if seen[key] {
					changed = true
					depth += strings.Count(line, "{") - strings.Count(line, "}")
					if depth <= 0 {
						flushLocation()
					}
					continue
				}
				seen[key] = true
			}
			out = append(out, line)
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				flushLocation()
			}
			continue
		}

		out = append(out, line)
	}
	return strings.Join(out, "\n"), changed
}

func singletonDirectiveKey(line string) string {
	line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	for _, prefix := range singletonLocationDirectives {
		if strings.HasPrefix(line, prefix) {
			return prefix
		}
	}
	return ""
}
