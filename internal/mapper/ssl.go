package mapper

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mercadolibre/serverpilot/internal/nginx"
)

const certbotPath = "/usr/bin/certbot"
const systemctlPath = "/usr/bin/systemctl"

// SSLStatus represents the SSL status for a domain.
type SSLStatus struct {
	Domain    string    `json:"domain"`
	Enabled   bool      `json:"enabled"`
	CertPath  string    `json:"cert_path,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// EnableSSL runs certbot to obtain and configure an SSL certificate for the domain.
func EnableSSL(domain string) error {
	if !nginx.IsValidDomainExported(domain) {
		return fmt.Errorf("invalid domain format")
	}

	cmd := exec.Command(certbotPath, "--nginx", "-d", domain, "--non-interactive", "--agree-tos")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certbot failed: %s", string(output))
	}

	return nil
}

// DisableSSL removes SSL configuration from the nginx site.
// This is done by re-parsing the config and rewriting it without SSL directives.
func DisableSSL(domain string) error {
	if !nginx.IsValidDomainExported(domain) {
		return fmt.Errorf("invalid domain format")
	}

	sites, err := nginx.ListSites()
	if err != nil {
		return fmt.Errorf("failed to list sites: %w", err)
	}

	var targetSite *nginx.Site
	for _, s := range sites {
		if s.Domain == domain {
			targetSite = &s
			break
		}
	}

	if targetSite == nil {
		return fmt.Errorf("site not found: %s", domain)
	}

	if !targetSite.SSLEnabled {
		return fmt.Errorf("SSL is not enabled for %s", domain)
	}

	// Use certbot to remove SSL.
	cmd := exec.Command(certbotPath, "delete", "--cert-name", domain, "--non-interactive")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certbot delete failed: %s", string(output))
	}

	return nginx.ReloadNginx()
}

// CheckSSLStatus checks if an SSL certificate exists for the domain and its expiry.
func CheckSSLStatus(domain string) (*SSLStatus, error) {
	if !nginx.IsValidDomainExported(domain) {
		return nil, fmt.Errorf("invalid domain format")
	}

	certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", domain)
	status := &SSLStatus{
		Domain: domain,
	}

	info, err := os.Stat(certPath)
	if err != nil {
		status.Enabled = false
		return status, nil
	}

	status.Enabled = true
	status.CertPath = certPath

	// Use certbot to check expiry.
	cmd := exec.Command(certbotPath, "certificates", "--cert-name", domain)
	output, err := cmd.CombinedOutput()
	if err == nil {
		// Parse expiry from certbot output.
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Expiry Date:") {
				dateStr := strings.TrimPrefix(line, "Expiry Date:")
				dateStr = strings.TrimSpace(dateStr)
				// Certbot format: "2024-03-15 12:00:00+00:00 (VALID: 89 days)"
				if idx := strings.Index(dateStr, " ("); idx != -1 {
					dateStr = dateStr[:idx]
				}
				if t, err := time.Parse("2006-01-02 15:04:05+00:00", dateStr); err == nil {
					status.ExpiresAt = t
				}
			}
		}
	}

	// Fallback: use file mod time if we couldn't parse.
	if status.ExpiresAt.IsZero() {
		status.ExpiresAt = info.ModTime().Add(90 * 24 * time.Hour) // Let's Encrypt certs are ~90 days
	}

	return status, nil
}

// SetupAutoRenew ensures the certbot auto-renewal timer is active.
func SetupAutoRenew() error {
	// Enable the certbot timer via systemctl.
	enableCmd := exec.Command(systemctlPath, "enable", "certbot.timer")
	if output, err := enableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable certbot timer: %s", string(output))
	}

	startCmd := exec.Command(systemctlPath, "start", "certbot.timer")
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start certbot timer: %s", string(output))
	}

	return nil
}
