package cmd

import (
	"fmt"
	"os"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up ServerPilot dependencies and credentials",
	Long:  "Checks and installs Docker and Nginx, then creates admin credentials for the web dashboard.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("=== ServerPilot Setup ===")
		fmt.Println()

		fmt.Println("[1/2] Checking dependencies...")
		if err := deps.CheckAndInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking dependencies: %v\n", err)
			return err
		}
		fmt.Println("Dependencies OK.")
		fmt.Println()

		fmt.Println("[2/2] Setting up admin credentials...")
		if err := auth.SetupCredentials(); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up credentials: %v\n", err)
			return err
		}
		fmt.Println()

		fmt.Println("=== Setup Complete ===")
		fmt.Println("Run 'sp start' to launch the web dashboard.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
