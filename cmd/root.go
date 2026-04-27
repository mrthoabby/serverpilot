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

// commandsRequiringRoot lists subcommands that mutate /etc, /var, or /usr.
// PersistentPreRunE refuses non-root invocations of these — eliminates
// half-applied changes (e.g. nginx config written but reload failed) and
// gives the operator a single, readable error instead of a cryptic EACCES
// from somewhere deep in the call stack (CWE-250).
var commandsRequiringRoot = map[string]bool{
	"setup":       true,
	"start":       true,
	"stop":        true,
	"expose":      true,
	"update":      true,
	"credentials": true,
}

var rootCmd = &cobra.Command{
	Use:   "sp",
	Short: "Server management dashboard for Docker & Nginx",
	Long:  "ServerPilot is a CLI tool that manages Docker containers and Nginx sites on a server, with a web dashboard.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if commandsRequiringRoot[cmd.Name()] {
			if os.Geteuid() != 0 {
				return fmt.Errorf("%q must be run as root (try: sudo sp %s)", cmd.Name(), cmd.Name())
			}
		}
		return nil
	},
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
