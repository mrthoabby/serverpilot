package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the ServerPilot daemon",
	Long:  "Checks if the ServerPilot systemd service is running and displays its status.",
	RunE: func(cmd *cobra.Command, args []string) error {
		sysCmd := exec.Command("/usr/bin/systemctl", "status", serviceName)
		output, err := sysCmd.CombinedOutput()
		outStr := strings.TrimSpace(string(output))

		if err != nil {
			// systemctl status returns exit code 3 if the service is not running.
			if outStr != "" {
				fmt.Println(outStr)
			} else {
				fmt.Println("ServerPilot daemon is not installed or not running.")
				fmt.Println("Start it with: sp start -d")
			}
			return nil
		}

		fmt.Println(outStr)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
