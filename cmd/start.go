package cmd

import (
	"fmt"
	"os"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/web"
	"github.com/spf13/cobra"
)

var startPort int

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the ServerPilot web dashboard",
	Long:  "Verifies dependencies, loads credentials, and starts the web dashboard server.",
	RunE: func(cmd *cobra.Command, args []string) error {
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
	},
}

func init() {
	startCmd.Flags().IntVarP(&startPort, "port", "p", 8090, "Port to run the web dashboard on")
	rootCmd.AddCommand(startCmd)
}
