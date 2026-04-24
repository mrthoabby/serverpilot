package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the ServerPilot daemon",
	Long:  "Stops the ServerPilot systemd service if it is running.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !IsRunningAsDaemon() {
			fmt.Println("ServerPilot daemon is not running.")
			return nil
		}

		fmt.Println("Stopping ServerPilot daemon...")

		stopCmd := exec.Command("/usr/bin/systemctl", "stop", serviceName)
		if output, err := stopCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to stop daemon: %s", strings.TrimSpace(string(output)))
		}

		fmt.Println("  ✓ ServerPilot daemon stopped.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
