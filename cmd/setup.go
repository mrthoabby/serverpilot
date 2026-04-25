package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up ServerPilot dependencies and credentials",
	Long:  "Checks and installs Docker and Nginx, creates admin credentials, and optionally configures SSL for the web dashboard.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("=== ServerPilot Setup ===")
		fmt.Println()

		fmt.Println("[1/3] Checking dependencies...")
		if err := deps.CheckAndInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking dependencies: %v\n", err)
			return err
		}
		fmt.Println("Dependencies OK.")
		fmt.Println()

		fmt.Println("[2/3] Setting up admin credentials...")
		if err := auth.SetupCredentials(); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up credentials: %v\n", err)
			return err
		}
		fmt.Println()

		fmt.Println("[3/3] SSL Configuration (optional)")
		if err := setupSSL(); err != nil {
			// SSL setup failure is non-fatal — the dashboard works without SSL.
			fmt.Fprintf(os.Stderr, "SSL setup skipped or failed: %v\n", err)
			fmt.Println("You can enable SSL later from the Settings tab in the dashboard.")
			fmt.Println()
		}

		fmt.Println("=== Setup Complete ===")
		fmt.Println("Run 'sp start' to launch the web dashboard.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// setupSSL runs the interactive SSL configuration step during setup.
// It asks the user if they want HTTPS, collects domain/email/port,
// installs certbot, creates the nginx reverse proxy, runs certbot,
// and saves the config so the dashboard starts HTTPS-secured.
func setupSSL() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("  Enable SSL (HTTPS) for the dashboard? [y/N]: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	if input != "y" && input != "yes" {
		fmt.Println("  SSL setup skipped.")
		fmt.Println()
		return nil
	}

	// --- Collect domain ---
	fmt.Print("  Enter your domain (e.g. panel.myserver.com): ")
	domain, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read domain: %w", err)
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if !nginx.IsValidDomainExported(domain) {
		return fmt.Errorf("invalid domain format: %q — only alphanumeric characters, dots, and hyphens are allowed", domain)
	}

	// --- Collect email ---
	fmt.Print("  Enter your email (for Let's Encrypt notifications): ")
	email, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read email: %w", err)
	}
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}
	if len(email) > 254 {
		return fmt.Errorf("email too long")
	}

	// --- Collect port (default 8090) ---
	fmt.Print("  Dashboard port [8090]: ")
	portInput, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	portInput = strings.TrimSpace(portInput)
	port := 8090
	if portInput != "" {
		p, err := strconv.Atoi(portInput)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port number: %q — must be between 1 and 65535", portInput)
		}
		port = p
	}

	fmt.Println()
	fmt.Printf("  Domain: %s\n", domain)
	fmt.Printf("  Email:  %s\n", email)
	fmt.Printf("  Port:   %d\n", port)
	fmt.Println()

	// --- Step 1: Install certbot if needed ---
	fmt.Println("  [SSL 1/4] Checking certbot...")
	if err := deps.CheckAndInstallCertbot(); err != nil {
		return fmt.Errorf("certbot installation failed: %w", err)
	}

	// --- Step 2: Create nginx reverse proxy config ---
	fmt.Println("  [SSL 2/4] Creating Nginx reverse proxy config...")
	nginxConfig := nginx.ServerPilotTemplate(domain, port)
	configPath := filepath.Join("/etc/nginx/sites-available", domain)

	absPath, err := filepath.Abs(configPath)
	if err != nil || !strings.HasPrefix(absPath, "/etc/nginx/") {
		return fmt.Errorf("invalid nginx config path")
	}

	if err := os.WriteFile(absPath, []byte(nginxConfig), 0644); err != nil {
		return fmt.Errorf("failed to write nginx config: %w", err)
	}
	fmt.Printf("  ✓ Config written: %s\n", absPath)

	if err := nginx.EnableSite(domain); err != nil {
		return fmt.Errorf("failed to enable site: %w", err)
	}
	fmt.Println("  ✓ Site enabled")

	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}
	fmt.Println("  ✓ Nginx reloaded")
	fmt.Println()

	// --- Step 3: Run certbot ---
	fmt.Printf("  [SSL 3/4] Requesting SSL certificate for %s...\n", domain)

	certbotBin, err := deps.FindCertbot()
	if err != nil {
		return fmt.Errorf("certbot not found after installation: %w", err)
	}

	certArgs := buildCertbotArgs(certbotBin, domain, email)
	fmt.Printf("  Running: %s\n", strings.Join(certArgs, " "))
	fmt.Println()

	certCmd := exec.Command(certArgs[0], certArgs[1:]...)
	certCmd.Stdout = os.Stdout
	certCmd.Stderr = os.Stderr

	if err := certCmd.Run(); err != nil {
		return fmt.Errorf("certbot failed: %w — you can retry SSL from the dashboard Settings tab", err)
	}

	fmt.Println()
	fmt.Println("  ✓ SSL certificate obtained")

	// Reload nginx after certbot modified the config.
	if err := nginx.ReloadNginx(); err != nil {
		fmt.Fprintf(os.Stderr, "  WARNING: nginx reload after certbot failed: %v\n", err)
	} else {
		fmt.Println("  ✓ Nginx reloaded with SSL")
	}

	// --- Step 4: Save config ---
	fmt.Println("  [SSL 4/4] Saving configuration...")

	config, err := auth.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	config.Domain = domain
	config.Email = email
	config.SSLEnabled = true
	config.InsecureBlocked = true

	if err := auth.SaveConfig(*config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("  ✓ Configuration saved")
	fmt.Println()
	fmt.Printf("  SSL enabled! Dashboard will be available at:\n")
	fmt.Printf("  https://%s\n", domain)
	fmt.Println()

	return nil
}

// buildCertbotArgs constructs the certbot command arguments for SSL setup.
func buildCertbotArgs(certbotBin, domain, email string) []string {
	args := []string{
		certbotBin,
		"--nginx",
		"-d", domain,
		"--non-interactive",
		"--agree-tos",
		"--email", email,
		"--redirect",
	}
	return args
}
