package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

type githubTag struct {
	Name string `json:"name"`
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Self-update ServerPilot to the latest version",
	Long:  "Fetches the latest release from GitHub and replaces the current binary.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Checking for updates...")

		latestVersion, err := fetchLatestTag()
		if err != nil {
			return fmt.Errorf("failed to check for updates: %w", err)
		}

		current := strings.TrimPrefix(version, "v")
		latest := strings.TrimPrefix(latestVersion, "v")

		if current == latest {
			fmt.Printf("Already up to date (v%s).\n", current)
			return nil
		}

		fmt.Printf("Current version: v%s\n", current)
		fmt.Printf("Latest version:  v%s\n", latest)
		fmt.Println("Downloading update...")

		if err := downloadAndReplace(latestVersion); err != nil {
			return fmt.Errorf("failed to update: %w", err)
		}

		fmt.Printf("Successfully updated to v%s.\n", latest)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func fetchLatestTag() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/mrthoabby/serverpilot/tags?per_page=1")
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository")
	}

	return tags[0].Name, nil
}

func downloadAndReplace(tagVersion string) error {
	osName := runtime.GOOS
	archName := runtime.GOARCH

	downloadURL := fmt.Sprintf(
		"https://github.com/mrthoabby/serverpilot/releases/download/%s/sp-%s-%s",
		tagVersion, osName, archName,
	)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}

	// Generate a random suffix for the temp file using crypto/rand.
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	randSuffix := hex.EncodeToString(randBytes)
	tmpPath := execPath + ".tmp-" + randSuffix

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write update: %w", err)
	}
	tmpFile.Close()

	// Atomic replace: rename the temp file over the current binary.
	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}
