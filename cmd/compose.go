package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
  REGISTRY_USER / REGISTRY_TOKEN (optional, ephemeral ghcr.io login)

Example:
  export IMAGE_REF=ghcr.io/org/app:v1.2.3
  sp compose release --name myapp --service app`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if composeProject == "" {
			return fmt.Errorf("--name is required")
		}
		return compose.ReleaseCLI(compose.ReleaseRequest{
			Name:     composeProject,
			Service:  composeReleaseService,
			ImageRef: os.Getenv("IMAGE_REF"),
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

	composeCmd.AddCommand(composeValidateCmd, composeDeployCmd, composeListCmd, composeStatusCmd, composeCloneCmd, composeSyncCmd, composeReleaseCmd, composeDeleteCmd)
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
