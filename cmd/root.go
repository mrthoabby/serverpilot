package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version     string
	showVersion bool
)

// SetVersion sets the application version from main.
func SetVersion(v string) {
	version = v
}

var rootCmd = &cobra.Command{
	Use:   "sp",
	Short: "Server management dashboard for Docker & Nginx",
	Long:  "ServerPilot is a CLI tool that manages Docker containers and Nginx sites on a server, with a web dashboard.",
	Run: func(cmd *cobra.Command, args []string) {
		if showVersion {
			fmt.Printf("serverpilot v%s\n", version)
			return
		}
		_ = cmd.Help()
	},
}

func init() {
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
