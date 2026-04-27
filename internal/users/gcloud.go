package users

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ruleNameRegex restricts a GCP firewall rule name to the characters GCP
// itself allows (lowercase alnum + hyphen, must start with a letter, max 63).
// This is used by CloseFirewallPort to guarantee the user-supplied value
// flowing into the gcloud argv cannot start with "-" (which would be parsed
// as another flag) and cannot contain whitespace or shell metacharacters.
var ruleNameRegex = regexp.MustCompile(`^sp-[a-z0-9-]{1,60}$`)

// GCloudStatus reports whether gcloud is available and configured.
type GCloudStatus struct {
	Available bool   `json:"available"`
	Project   string `json:"project,omitempty"`
	Account   string `json:"account,omitempty"`
}

// FirewallRule represents a simplified GCP firewall rule.
type FirewallRule struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Allowed   string `json:"allowed"`
	SourceIP  string `json:"source_ranges"`
	Disabled  bool   `json:"disabled"`
}

// CheckGCloud detects whether the gcloud CLI is installed and configured.
func CheckGCloud() GCloudStatus {
	status := GCloudStatus{}

	// Check if gcloud binary exists.
	path, err := exec.LookPath("gcloud")
	if err != nil || path == "" {
		return status
	}
	status.Available = true

	// Get active project.
	out, err := exec.Command("gcloud", "config", "get-value", "project", "--quiet").Output()
	if err == nil {
		status.Project = strings.TrimSpace(string(out))
	}

	// Get active account.
	out, err = exec.Command("gcloud", "config", "get-value", "account", "--quiet").Output()
	if err == nil {
		status.Account = strings.TrimSpace(string(out))
	}

	return status
}

// ListFirewallRules returns all firewall rules in the active project.
func ListFirewallRules() ([]FirewallRule, error) {
	if !CheckGCloud().Available {
		return nil, fmt.Errorf("gcloud not available")
	}

	out, err := exec.Command("gcloud", "compute", "firewall-rules", "list",
		"--format=json", "--quiet").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewall rules: %w", err)
	}

	var rawRules []struct {
		Name         string `json:"name"`
		Direction    string `json:"direction"`
		Disabled     bool   `json:"disabled"`
		SourceRanges []string `json:"sourceRanges"`
		Allowed      []struct {
			IPProtocol string   `json:"IPProtocol"`
			Ports      []string `json:"ports"`
		} `json:"allowed"`
	}

	if err := json.Unmarshal(out, &rawRules); err != nil {
		return nil, fmt.Errorf("failed to parse firewall rules: %w", err)
	}

	var rules []FirewallRule
	for _, r := range rawRules {
		var allowed []string
		for _, a := range r.Allowed {
			if len(a.Ports) > 0 {
				allowed = append(allowed, a.IPProtocol+":"+strings.Join(a.Ports, ","))
			} else {
				allowed = append(allowed, a.IPProtocol+":all")
			}
		}
		rules = append(rules, FirewallRule{
			Name:      r.Name,
			Direction: r.Direction,
			Allowed:   strings.Join(allowed, "; "),
			SourceIP:  strings.Join(r.SourceRanges, ", "),
			Disabled:  r.Disabled,
		})
	}

	return rules, nil
}

// OpenFirewallPort creates a GCP firewall rule that allows TCP traffic on the
// specified port from the given source range (default 0.0.0.0/0).
//
// Hardening (CWE-78 / CWE-99): the previous version concatenated the
// caller-supplied sourceRange directly into a `--source-ranges=` argument
// without re-validating. While the higher-level web handler validated, this
// function is also called from other code paths and from a future API; we
// re-validate at the SDK boundary to fail-closed regardless of caller.
func OpenFirewallPort(port int, sourceRange string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if sourceRange == "" {
		sourceRange = "0.0.0.0/0"
	}
	canonical, err := canonicalCIDR(sourceRange)
	if err != nil {
		return fmt.Errorf("invalid source range")
	}

	ruleName := fmt.Sprintf("sp-allow-tcp-%d", port)

	cmd := exec.Command("gcloud", "compute", "firewall-rules", "create", ruleName,
		"--direction=INGRESS",
		"--action=ALLOW",
		"--rules=tcp:"+strconv.Itoa(port),
		"--source-ranges="+canonical,
		"--description=Opened by ServerPilot",
		"--quiet",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Do NOT echo gcloud's stderr back to the caller — it may contain
		// project/account hints. Log internally; surface a generic error.
		return fmt.Errorf("gcloud command failed (%d bytes of output suppressed)", len(out))
	}
	return nil
}

// canonicalCIDR parses a single IPv4 address or IPv4 CIDR and returns the
// canonical CIDR string. Refuses anything that does not parse cleanly.
func canonicalCIDR(s string) (string, error) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return "", err
		}
		return n.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("not an IPv4 address")
	}
	return ip.String() + "/32", nil
}

// CloseFirewallPort deletes a GCP firewall rule by name.
// Only allows deleting rules prefixed with "sp-" (created by ServerPilot).
func CloseFirewallPort(ruleName string) error {
	if ruleName == "" {
		return fmt.Errorf("rule name is required")
	}
	// Strict allowlist. The caller may have already checked the prefix, but
	// argument-injection defenses must live at the SDK boundary too — the
	// regex refuses any leading "-" (which gcloud would parse as a flag) and
	// any character outside [a-z0-9-]. This is what GCP itself accepts.
	if !ruleNameRegex.MatchString(ruleName) {
		return fmt.Errorf("invalid rule name format")
	}

	cmd := exec.Command("gcloud", "compute", "firewall-rules", "delete", ruleName, "--quiet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gcloud command failed (%d bytes of output suppressed)", len(out))
	}
	return nil
}
