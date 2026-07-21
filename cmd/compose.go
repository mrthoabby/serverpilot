package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/compose"
	"github.com/spf13/cobra"
)

var (
	composeFilePath       string
	composeProject        string
	composeAlias          string
	composeJSON           bool
	composeNonInteractive bool
	composeParent         string
	composeShareConfirm   bool
	composeReleaseService string
	composeReleaseImage   string
	composeStrategy       string
	composeHealthURL      string
	composeHealthWait     time.Duration
	composeDrain          time.Duration
	composeSkipEnsureDeps bool
	composeExceptService  string
)

var composeCmd = &cobra.Command{
	Use:   "compose",
	Short: "Manage Docker Compose projects",
	Long: `Deploy, validate, clone and manage Docker Compose projects under /opt.

Published ports must use ${SP_COMPOSE_PORT} or ${SP_COMPOSE_PORT_<SERVICE>_<PORT>}
variables. ServerPilot reserves localhost ports and injects them at deploy time.`,
}

var composeValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a compose project without deploying",
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		if composeFilePath == "" {
			return fmt.Errorf("--file is required")
		}
		root := projectRootFromFile(composeFilePath)
		res, err := compose.AnalyzeProjectStrict(composeProject, root, composeFilePath)
		if err != nil {
			return err
		}
		return printComposeJSON(res)
	},
}

var composeDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy a compose project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRootForComposeMutation(); err != nil {
			return err
		}
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		if composeFilePath == "" {
			return fmt.Errorf("--file is required")
		}
		root := projectRootFromFile(composeFilePath)
		rec, err := compose.Deploy(compose.DeployRequest{
			Name:          composeProject,
			Alias:         composeAlias,
			RootDir:       root,
			ComposeFile:   composeFilePath,
			AppImageRef:   os.Getenv("IMAGE_REF"),
			RegistryUser:  os.Getenv("REGISTRY_USER"),
			RegistryToken: os.Getenv("REGISTRY_TOKEN"),
		}, composeProgress())
		if err != nil {
			return err
		}
		return printComposeJSON(rec)
	},
}

var composeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered compose projects",
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = compose.RefreshOutdatedFlags()
		items, err := compose.ListProjects()
		if err != nil {
			return err
		}
		return printComposeJSON(items)
	},
}

var composeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show one compose project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		_ = compose.RefreshOutdatedFlags()
		rec, ok, err := compose.GetProject(composeProject)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("compose project not found")
		}
		return printComposeJSON(rec)
	},
}

var composeCloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Clone a complete compose stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRootForComposeMutation(); err != nil {
			return err
		}
		if composeParent == "" || composeProject == "" {
			return fmt.Errorf("--parent and --name are required")
		}
		req := compose.CloneRequest{
			ParentName:   composeParent,
			CloneName:    composeProject,
			Alias:        composeAlias,
			Mounts:       map[string]compose.VolumePolicy{},
			ShareConfirm: composeShareConfirm,
		}
		analysis, _, err := compose.PreviewClone(composeParent, composeProject)
		if err != nil {
			return err
		}
		for _, mount := range analysis.Mounts {
			if !mount.Supported {
				continue
			}
			if composeNonInteractive {
				req.Mounts[mount.Key] = compose.VolumePolicyEmpty
				continue
			}
			req.Mounts[mount.Key] = compose.VolumePolicyEmpty
		}
		rec, err := compose.Clone(req, composeProgress())
		if err != nil {
			return err
		}
		return printComposeJSON(rec)
	},
}

var composeSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Resync an outdated compose clone from its parent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRootForComposeMutation(); err != nil {
			return err
		}
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		rec, err := compose.SyncClone(composeProject, compose.CloneRequest{
			ShareConfirm: composeShareConfirm,
			Mounts:       map[string]compose.VolumePolicy{},
		}, composeProgress())
		if err != nil {
			return err
		}
		return printComposeJSON(rec)
	},
}

var composeReleaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Pull and recreate one service after CI (Camino 2)",
	Long: `Updates a single service in a project already bootstrapped with sp compose deploy.

Works like sp port: run the command as your SSH user; ServerPilot handles privileged work.

Requires environment variables:
  IMAGE_REF (required)
  COMPOSE_FILE (optional, default docker-compose.yml — only used on first release bootstrap)
  REGISTRY_USER / REGISTRY_TOKEN (optional, ephemeral ghcr.io login)

Example:
  export IMAGE_REF=ghcr.io/org/app:v1.2.3
  sp compose release --name myapp --file docker-compose.yml --service app`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		file := composeFilePath
		if file == "" {
			file = os.Getenv("COMPOSE_FILE")
		}
		return compose.ReleaseCLI(compose.ReleaseRequest{
			Name:           composeProject,
			Service:        composeReleaseService,
			ComposeFile:    file,
			ImageRef:       firstNonEmptyEnv(composeReleaseImage, os.Getenv("IMAGE_REF")),
			RegistryUser:   os.Getenv("REGISTRY_USER"),
			RegistryToken:  os.Getenv("REGISTRY_TOKEN"),
			Strategy:       composeStrategy,
			HealthURL:      composeHealthURL,
			HealthTimeout:  composeHealthWait,
			Drain:          composeDrain,
			SkipEnsureDeps: composeSkipEnsureDeps,
		}, composeProgress())
	},
}

var composeDepsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Manage compose dependency services",
}

var composeDepsUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Ensure long-running compose dependencies are healthy",
	Long: `Starts or recreates dependency services (restart != "no") and waits for healthchecks.

Use before migrations or when shared deps (db, redis, search) may be down.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		file := composeFilePath
		if file == "" {
			file = os.Getenv("COMPOSE_FILE")
		}
		except := composeExceptService
		if except == "" {
			except = os.Getenv("RELEASE_SERVICE")
		}
		return compose.DepsUpCLI(compose.EnsureDepsRequest{
			Name:          composeProject,
			ComposeFile:   file,
			ExceptService: except,
			ImageRef:      firstNonEmptyEnv(composeReleaseImage, os.Getenv("IMAGE_REF")),
			RegistryUser:  os.Getenv("REGISTRY_USER"),
			RegistryToken: os.Getenv("REGISTRY_TOKEN"),
		}, composeProgress())
	},
}

var composeRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a one-shot compose service",
	Long: `Ensures dependencies are healthy, then runs a restart: "no" service (e.g. migrations).

Requires IMAGE_REF when the service image uses ${IMAGE_REF}.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		if composeReleaseService == "" {
			return fmt.Errorf("--service is required")
		}
		file := composeFilePath
		if file == "" {
			file = os.Getenv("COMPOSE_FILE")
		}
		return compose.RunCLI(compose.RunServiceRequest{
			Name:          composeProject,
			ComposeFile:   file,
			Service:       composeReleaseService,
			Args:          args,
			ImageRef:      firstNonEmptyEnv(composeReleaseImage, os.Getenv("IMAGE_REF")),
			RegistryUser:  os.Getenv("REGISTRY_USER"),
			RegistryToken: os.Getenv("REGISTRY_TOKEN"),
		}, composeProgress())
	},
}

var composeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a compose project stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRootForComposeMutation(); err != nil {
			return err
		}
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		if err := compose.DeleteProjectStack(composeProject, composeProgress()); err != nil {
			return err
		}
		if composeJSON {
			fmt.Println(`{"success":true}`)
		} else {
			fmt.Println("Compose project deleted.")
		}
		return nil
	},
}

func init() {
	composeCmd.PersistentFlags().StringVar(&composeProject, "name", "", "Compose project name")
	composeCmd.PersistentFlags().StringVar(&composeFilePath, "file", "", "Path to docker-compose.yml")
	composeCmd.PersistentFlags().StringVar(&composeAlias, "alias", "", "Visible alias in the dashboard")
	composeCmd.PersistentFlags().BoolVar(&composeJSON, "json", false, "Emit machine-readable JSON")
	composeCmd.PersistentFlags().BoolVar(&composeNonInteractive, "non-interactive", false, "Fail instead of prompting")
	composeCmd.PersistentFlags().StringVar(&composeParent, "parent", "", "Parent compose project for clone/sync")
	composeCmd.PersistentFlags().BoolVar(&composeShareConfirm, "share-confirm", false, "Confirm writable shared volumes")
	composeReleaseCmd.Flags().StringVar(&composeReleaseService, "service", "app", "Compose service to update")
	composeReleaseCmd.Flags().StringVar(&composeReleaseImage, "image", "", "Image reference (default: IMAGE_REF env)")
	composeReleaseCmd.Flags().StringVar(&composeStrategy, "strategy", compose.StrategyRolling, "Deployment strategy: rolling or blue-green")
	composeReleaseCmd.Flags().StringVar(&composeHealthURL, "health-url", "", "Optional HTTP health check path (e.g. /health)")
	composeReleaseCmd.Flags().DurationVar(&composeHealthWait, "health-timeout", 3*time.Minute, "Health check timeout")
	composeReleaseCmd.Flags().DurationVar(&composeDrain, "drain", 10*time.Second, "Drain period before removing old color")
	composeReleaseCmd.Flags().BoolVar(&composeSkipEnsureDeps, "no-ensure-deps", false, "Skip dependency health check before release")
	composeDepsUpCmd.Flags().StringVar(&composeExceptService, "except-service", "", "Exclude this service from dependency ensure (default: RELEASE_SERVICE env)")
	composeDepsUpCmd.Flags().StringVar(&composeReleaseImage, "image", "", "Image reference for compose interpolation (default: IMAGE_REF env)")
	composeRunCmd.Flags().StringVar(&composeReleaseService, "service", "", "One-shot compose service to run")
	composeRunCmd.Flags().StringVar(&composeReleaseImage, "image", "", "Image reference (default: IMAGE_REF env)")

	composeDepsCmd.AddCommand(composeDepsUpCmd)
	composeCmd.AddCommand(composeValidateCmd, composeDeployCmd, composeListCmd, composeStatusCmd, composeCloneCmd, composeSyncCmd, composeReleaseCmd, composeDepsCmd, composeRunCmd, composeDeleteCmd)
	rootCmd.AddCommand(composeCmd)
}

func projectRootFromFile(file string) string {
	if filepath.IsAbs(file) {
		return filepath.Dir(file)
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return filepath.Dir(file)
	}
	return filepath.Dir(abs)
}

func printComposeJSON(v any) error {
	if !composeJSON {
		fmt.Printf("%v\n", v)
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func composeProgress() compose.Progress {
	return func(msg string) {
		_, _ = os.Stdout.WriteString(msg + "\n")
	}
}

func requireRootForComposeMutation() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this compose command must be run as root (try: sudo sp compose ...)")
	}
	return nil
}

func firstNonEmptyEnv(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
