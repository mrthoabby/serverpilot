package cmd

import (
	"fmt"
	"os"

	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/spf13/cobra"
)

var (
	sitesContainer     string
	sitesContainerID   string
	sitesContainerPort string
)

var sitesCmd = &cobra.Command{
	Use:   "sites",
	Short: "Manage nginx sites linked to containers",
}

var sitesHostPortCmd = &cobra.Command{
	Use:   "host-port",
	Short: "Print the registry host port for a linked container",
	Long: `Returns the host port ServerPilot/nginx uses for sites linked to a container.

Used by Camino A deploy scripts to keep docker -p aligned with existing sites.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return sites.HostPortCLI(sitesContainer)
	},
}

var sitesSyncPortCmd = &cobra.Command{
	Use:   "sync-port",
	Short: "Repoint linked sites to the container's current published port",
	Long: `Updates nginx proxy_pass for every site linked to a container so it matches
the container's current host port. Safe to run after docker run releases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if sitesContainer == "" && sitesContainerID == "" {
			return fmt.Errorf("--container or --container-id is required")
		}
		if os.Geteuid() == 0 {
			port, err := docker.SyncLinkedContainerSites(sitesContainer, sitesContainerID, sitesContainerPort)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Synced nginx to host port %d\n", port)
			return nil
		}
		return sites.SyncPortCLI(sitesContainer, sitesContainerID, sitesContainerPort)
	},
}

func init() {
	sitesHostPortCmd.Flags().StringVar(&sitesContainer, "container", "", "Container name")
	sitesSyncPortCmd.Flags().StringVar(&sitesContainer, "container", "", "Container name")
	sitesSyncPortCmd.Flags().StringVar(&sitesContainerID, "container-id", "", "Container ID (optional)")
	sitesSyncPortCmd.Flags().StringVar(&sitesContainerPort, "container-port", "3000", "Container TCP port")
	sitesCmd.AddCommand(sitesHostPortCmd, sitesSyncPortCmd)
	rootCmd.AddCommand(sitesCmd)
}
