package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/mrthoabby/serverpilot/internal/compose"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/spf13/cobra"
)

var (
	releaseContainer  string
	releaseImage      string
	releaseStrategy   string
	releaseHealthURL  string
	releaseHealthWait time.Duration
	releaseDrain      time.Duration
)

var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Blue-green release for a standalone Docker container with an Nginx site",
	Long: `Updates a standalone container using blue-green deployment when --strategy blue-green.

Requires at least one ServerPilot-managed Nginx site linked to the container.
Compose-managed containers must use: sp compose release --strategy blue-green

Example:
  sudo sp release --container myapi --image ghcr.io/org/api:v2 \
    --strategy blue-green --health-url /health --drain 10s`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if releaseContainer == "" {
			return fmt.Errorf("--container is required")
		}
		if compose.ParseStrategy(releaseStrategy) != compose.StrategyBlueGreen {
			return fmt.Errorf("sp release currently supports only --strategy blue-green")
		}
		return docker.ReleaseBlueGreenProgress(docker.BlueGreenRequest{
			Container:     releaseContainer,
			Image:         releaseImage,
			HealthURL:     releaseHealthURL,
			HealthTimeout: releaseHealthWait,
			Drain:         releaseDrain,
		}, func(msg string) {
			_, _ = os.Stdout.WriteString(msg + "\n")
		})
	},
}

func init() {
	releaseCmd.Flags().StringVar(&releaseContainer, "container", "", "Container name or ID")
	releaseCmd.Flags().StringVar(&releaseImage, "image", os.Getenv("IMAGE_REF"), "New image reference (default: IMAGE_REF env)")
	releaseCmd.Flags().StringVar(&releaseStrategy, "strategy", compose.StrategyRolling, "Deployment strategy: rolling or blue-green")
	releaseCmd.Flags().StringVar(&releaseHealthURL, "health-url", "", "Optional HTTP health check path (e.g. /health)")
	releaseCmd.Flags().DurationVar(&releaseHealthWait, "health-timeout", 60*time.Second, "Health check timeout")
	releaseCmd.Flags().DurationVar(&releaseDrain, "drain", 10*time.Second, "Drain period before removing old color")
	rootCmd.AddCommand(releaseCmd)
}
