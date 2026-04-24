package cmd

import (
	"fmt"

	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/templates"
	"github.com/spf13/cobra"
)

var (
	exposeDomain string
	exposePort   int
)

var exposeCmd = &cobra.Command{
	Use:   "expose",
	Short: "Expose the ServerPilot dashboard through Nginx reverse proxy",
	Long: `Creates an Nginx reverse proxy configuration so the ServerPilot dashboard
is accessible from outside via a domain name.

Example:
  sp expose --domain panel.myserver.com
  sp expose --domain panel.myserver.com --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if exposeDomain == "" {
			return fmt.Errorf("--domain is required\n\nUsage: sp expose --domain <your-domain> [--port <dashboard-port>]")
		}

		// Validate domain format.
		if !nginx.IsValidDomainExported(exposeDomain) {
			return fmt.Errorf("invalid domain format: %q — only alphanumeric characters, dots, and hyphens are allowed", exposeDomain)
		}

		// Validate port range.
		if exposePort < 1 || exposePort > 65535 {
			return fmt.Errorf("invalid port number: %d — must be between 1 and 65535", exposePort)
		}

		// Verify that Nginx is installed before proceeding.
		if err := deps.Verify(); err != nil {
			return fmt.Errorf("dependency check failed: %w\nRun 'sp setup' first to install required dependencies", err)
		}

		fmt.Printf("Exposing ServerPilot dashboard via Nginx...\n\n")
		fmt.Printf("  Domain:         %s\n", exposeDomain)
		fmt.Printf("  Dashboard port: %d\n", exposePort)
		fmt.Println()

		// Use the API template (standard reverse proxy) pointing to the dashboard.
		if err := templates.ApplyTemplate(templates.API, exposeDomain, exposePort); err != nil {
			return fmt.Errorf("failed to expose dashboard: %w", err)
		}

		fmt.Printf("  ✓ Nginx config created: /etc/nginx/sites-available/%s\n", exposeDomain)
		fmt.Printf("  ✓ Site enabled in /etc/nginx/sites-enabled/\n")
		fmt.Printf("  ✓ Nginx reloaded\n")
		fmt.Println()
		fmt.Printf("Dashboard is now accessible at:\n")
		fmt.Printf("  http://%s\n", exposeDomain)
		fmt.Println()
		fmt.Printf("To enable HTTPS, run:\n")
		fmt.Printf("  sp start  (if not already running)\n")
		fmt.Printf("  Then use the dashboard to enable SSL for %s,\n", exposeDomain)
		fmt.Printf("  or run: certbot --nginx -d %s\n", exposeDomain)

		return nil
	},
}

func init() {
	exposeCmd.Flags().StringVar(&exposeDomain, "domain", "", "Domain name to expose the dashboard (required)")
	exposeCmd.Flags().IntVar(&exposePort, "port", 8090, "Dashboard port to proxy (default 8090)")
	rootCmd.AddCommand(exposeCmd)
}
