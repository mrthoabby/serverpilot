package users

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

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
// The rule name is auto-generated as "sp-allow-tcp-<port>".
func OpenFirewallPort(port int, sourceRange string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}
	if sourceRange == "" {
		sourceRange = "0.0.0.0/0"
	}

	ruleName := fmt.Sprintf("sp-allow-tcp-%d", port)

	cmd := exec.Command("gcloud", "compute", "firewall-rules", "create", ruleName,
		"--direction=INGRESS",
		"--action=ALLOW",
		"--rules=tcp:"+strconv.Itoa(port),
		"--source-ranges="+sourceRange,
		"--description=Opened by ServerPilot",
		"--quiet",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gcloud failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// CloseFirewallPort deletes a GCP firewall rule by name.
// Only allows deleting rules prefixed with "sp-" (created by ServerPilot).
func CloseFirewallPort(ruleName string) error {
	if ruleName == "" {
		return fmt.Errorf("rule name is required")
	}
	// Safety: only delete rules created by ServerPilot.
	if !strings.HasPrefix(ruleName, "sp-") {
		return fmt.Errorf("can only delete ServerPilot-managed rules (prefix 'sp-')")
	}

	cmd := exec.Command("gcloud", "compute", "firewall-rules", "delete", ruleName, "--quiet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gcloud failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}
