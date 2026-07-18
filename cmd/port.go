package cmd

import (
	"fmt"
	"os"

	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/spf13/cobra"
)

var (
	portMin  int
	portMax  int
	portList bool
)

var portCmd = &cobra.Command{
	Use:   "port",
	Short: "Allocate the next available port (default range 3000-3999)",
	Long: `Scans a port range and returns the first port that is:
  1. Not bound by any running process
  2. Not reserved by another ServerPilot owner
  3. Not already used by Docker or an existing Nginx proxy_pass site

Before allocating, ServerPilot refreshes its registry from Docker and Nginx
so ports used by stopped/restarting containers with existing sites remain
blocked. Anonymous allocations are locked for 1 minute so concurrent callers
never receive the same port. Permanent owner reservations stay assigned
across restarts and are held for 14 days after the endpoint stops listening
before the port can be reassigned.

Examples:
  sp port                  # returns a port in 3000-3999
  sp port --min 4000 --max 4999   # custom range
  sp port --list           # show currently reserved ports`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if portList {
			reservations, err := portalloc.SyncAndListInfosCLI(portMin, portMax)
			if err != nil {
				return fmt.Errorf("port registry sync failed: %w", err)
			}
			if len(reservations) == 0 {
				fmt.Fprintln(os.Stderr, "No active reservations.")
				return nil
			}
			fmt.Fprintf(os.Stderr, "Active reservations (%d):\n", len(reservations))
			for _, r := range reservations {
				if r.Owner != "" {
					line := fmt.Sprintf("  port %-5d  reserved for %s (%s)", r.Port, r.Owner, r.Status)
					if r.ReleaseAt != nil {
						line += fmt.Sprintf(", release after %s", r.ReleaseAt.Format("2006-01-02 15:04"))
					}
					fmt.Fprintln(os.Stderr, line)
					continue
				}
				fmt.Fprintf(os.Stderr, "  port %-5d  locked until %s (%s)\n", r.Port, r.ExpiresAt.Format("15:04:05"), r.Status)
			}
			return nil
		}

		port, err := portalloc.AllocateCLI(portMin, portMax)
		if err != nil {
			return fmt.Errorf("port allocation failed: %w", err)
		}

		// Print ONLY the port number to stdout so scripts can capture it:
		//   PORT=$(sp port)
		fmt.Println(port)
		return nil
	},
}

func init() {
	portCmd.Flags().IntVar(&portMin, "min", portalloc.DefaultMinPort, "Start of port range")
	portCmd.Flags().IntVar(&portMax, "max", portalloc.DefaultMaxPort, "End of port range")
	portCmd.Flags().BoolVar(&portList, "list", false, "List currently reserved ports")
	rootCmd.AddCommand(portCmd)
}
