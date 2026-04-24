package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/web"
	"github.com/spf13/cobra"
)

const (
	serviceName = "serverpilot"
	serviceFile = "/etc/systemd/system/serverpilot.service"
	pidFile     = "/var/run/serverpilot.pid"
)

var (
	startPort   int
	startDaemon bool
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the ServerPilot web dashboard",
	Long: `Verifies dependencies, loads credentials, and starts the web dashboard server.

Use --daemon (-d) to run in background as a systemd service.
Without --daemon, runs in the foreground (blocks the terminal).

Examples:
  sp start              # foreground (Ctrl+C to stop)
  sp start -d           # daemon mode via systemd
  sp start -d -p 9090   # daemon on port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if startDaemon {
			return startAsDaemon()
		}
		return startForeground()
	},
}

func init() {
	startCmd.Flags().IntVarP(&startPort, "port", "p", 8090, "Port to run the web dashboard on")
	startCmd.Flags().BoolVarP(&startDaemon, "daemon", "d", false, "Run as a background daemon (systemd service)")
	rootCmd.AddCommand(startCmd)
}

// startForeground runs the server in the current terminal (blocking).
func startForeground() error {
	fmt.Println("=== Starting ServerPilot ===")

	fmt.Println("Verifying dependencies...")
	if err := deps.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "Dependency check failed: %v\n", err)
		return err
	}

	fmt.Println("Loading configuration...")
	config, err := auth.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'sp setup' first to configure credentials.")
		return err
	}

	fmt.Printf("Dashboard available at: http://localhost:%d\n", startPort)
	fmt.Println("Press Ctrl+C to stop.")

	srv := web.NewServer(config, startPort)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		return err
	}

	return nil
}

// startAsDaemon installs and starts a systemd service for ServerPilot.
func startAsDaemon() error {
	fmt.Println("=== Starting ServerPilot (daemon mode) ===")

	// Verify dependencies first.
	fmt.Println("Verifying dependencies...")
	if err := deps.Verify(); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// Verify config exists.
	fmt.Println("Verifying configuration...")
	if _, err := auth.LoadConfig(); err != nil {
		return fmt.Errorf("configuration not found — run 'sp setup' first: %w", err)
	}

	// Find the current binary path for the ExecStart directive.
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	// Generate the systemd unit file.
	unitContent := generateServiceUnit(execPath, startPort)

	// Write the service file (requires root).
	if err := os.WriteFile(serviceFile, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file (are you running as root?): %w", err)
	}
	fmt.Printf("  ✓ Service file created: %s\n", serviceFile)

	// Reload systemd, enable and start the service.
	steps := []struct {
		desc string
		args []string
	}{
		{"Reloading systemd", []string{"/usr/bin/systemctl", "daemon-reload"}},
		{"Enabling service", []string{"/usr/bin/systemctl", "enable", serviceName}},
		{"Starting service", []string{"/usr/bin/systemctl", "restart", serviceName}},
	}

	for _, step := range steps {
		fmt.Printf("  %s...\n", step.desc)
		cmd := exec.Command(step.args[0], step.args[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %s", step.desc, strings.TrimSpace(string(output)))
		}
	}

	fmt.Println()
	fmt.Printf("  ✓ ServerPilot is running as a daemon on port %d\n", startPort)
	fmt.Println()
	fmt.Println("Useful commands:")
	fmt.Println("  sp stop              Stop the daemon")
	fmt.Printf("  sp status            Check daemon status\n")
	fmt.Printf("  journalctl -u %s -f  Follow logs\n", serviceName)

	return nil
}

// generateServiceUnit creates the systemd unit file content.
func generateServiceUnit(execPath string, port int) string {
	return fmt.Sprintf(`[Unit]
Description=ServerPilot Dashboard
After=network.target docker.service nginx.service
Wants=docker.service nginx.service

[Service]
Type=simple
ExecStart=%s start --port %d
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serverpilot

[Install]
WantedBy=multi-user.target
`, execPath, port)
}

// IsRunningAsDaemon checks if the systemd service is active.
func IsRunningAsDaemon() bool {
	cmd := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", serviceName)
	return cmd.Run() == nil
}

// RestartDaemon restarts the systemd service if it is running.
func RestartDaemon() error {
	if !IsRunningAsDaemon() {
		return nil
	}

	fmt.Println("Restarting ServerPilot daemon...")
	cmd := exec.Command("/usr/bin/systemctl", "restart", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart daemon: %s", strings.TrimSpace(string(output)))
	}
	fmt.Println("  ✓ Daemon restarted successfully.")
	return nil
}

// GetDaemonPort reads the port from the systemd service file if it exists.
func GetDaemonPort() int {
	data, err := os.ReadFile(serviceFile)
	if err != nil {
		return 8090
	}
	content := string(data)
	// Parse --port from ExecStart line.
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStart=") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "--port" && i+1 < len(parts) {
					if p, err := strconv.Atoi(parts[i+1]); err == nil {
						return p
					}
				}
			}
		}
	}
	return 8090
}
