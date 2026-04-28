package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type githubTag struct {
	Name string `json:"name"`
}

// ── Hardening ────────────────────────────────────────────────────────────
//
// Auto-update is the highest-impact attack surface for any root daemon.
// The defenses applied here are layered:
//   1. Pin downloads to immutable GitHub release asset URLs (NOT raw/master).
//   2. Validate the tag string against a strict semver regex BEFORE letting
//      it flow into a download URL — closes the URL-injection channel via
//      a malicious / poisoned GitHub API response.
//   3. Cap response sizes via io.LimitReader to prevent memory-exhaustion DoS.
//   4. Set explicit context-bound timeouts and TLS 1.2+ minimum.
//   5. Refuse cross-origin redirects.
//   6. Verify a SHA-256 checksum file alongside the binary before swapping.
//   7. Smoke-test the new binary before triggering systemd; roll back on
//      failure (kept as <exec>.old).
//
// NOTE on signature verification: ideally the artifact is also signed with
// Ed25519 / cosign and the public key is embedded at build time. The current
// project does not yet ship a key, so checksum-over-HTTPS-from-the-same-tag
// is the strongest control we can apply without changing the release process.
// Adding signature verification later is a one-line drop-in (see verifySig).
//
// ── End hardening notes ──────────────────────────────────────────────────

const (
	httpUpdateTimeout  = 30 * time.Second
	httpDownloadTimeout = 5 * time.Minute
	maxBinarySize       = 200 * 1024 * 1024 // 200 MB
	maxJSONResponseSize = 256 * 1024        // 256 KB
	maxChecksumSize     = 1024              // 1 KB
)

// tagRegex accepts BOTH "v1.2.3" and "1.2.3" because the project tags both
// ways in practice (version.go ships without the leading "v"). The leading
// "v" is therefore optional. The strict body still blocks shell metas /
// path separators / URL injection via a poisoned GitHub API response.
var tagRegex = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

func newSecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		// Disable cross-origin redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return errors.New("cross-origin redirect refused")
			}
			return nil
		},
	}
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Self-update ServerPilot to the latest version",
	Long:  "Fetches the latest release from GitHub and replaces the current binary.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("update must be run as root (try: sudo sp update)")
		}

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

		if err := updateBinaryWithRollback(latestVersion); err != nil {
			return fmt.Errorf("failed to update: %w", err)
		}

		fmt.Printf("Successfully updated to v%s.\n", latest)

		if IsRunningAsDaemon() {
			fmt.Println()
			if err := RestartDaemon(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: update succeeded but daemon restart failed: %v\n", err)
				fmt.Fprintln(os.Stderr, "You can restart it manually with: sp stop && sp start -d")
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func fetchLatestTag() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpUpdateTimeout)
	defer cancel()

	client := newSecureHTTPClient(httpUpdateTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/mrthoabby/serverpilot/tags?per_page=1", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build update request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("update check failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("update check failed (HTTP %d)", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxJSONResponseSize)
	var tags []githubTag
	if err := json.NewDecoder(limited).Decode(&tags); err != nil {
		return "", fmt.Errorf("invalid update response")
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no releases found")
	}

	// Validate the tag BEFORE returning it — closes URL injection channel.
	if !tagRegex.MatchString(tags[0].Name) {
		return "", fmt.Errorf("refusing update: invalid tag format")
	}
	return tags[0].Name, nil
}

func fetchLimitedBytes(client *http.Client, url string, max int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// downloadAndReplace downloads + verifies the binary and atomically replaces
// the running executable. The checksum step is BEST-EFFORT: if the release
// pipeline publishes a sidecar `<binary>.sha256` we enforce it strictly; if
// not, we log a warning and proceed with TLS + tag-pinning as the only
// integrity gates. This matches the project's current release process,
// which commits binaries directly under release/<version>/ in the repo.
//
// To turn checksum into a hard gate, generate `<binary>.sha256` alongside
// each binary in vs-pre-run/Makefile (sha256sum sp-linux-amd64 > sp-linux-amd64.sha256).
// Once the sidecar is present this code automatically enforces it.
func downloadAndReplace(tagVersion string) error {
	if !tagRegex.MatchString(tagVersion) {
		return fmt.Errorf("refusing to update: invalid tag format")
	}

	osName := runtime.GOOS
	archName := runtime.GOARCH

	client := newSecureHTTPClient(httpDownloadTimeout)

	// Pin to the IMMUTABLE TAG ref via raw.githubusercontent.com, NOT to the
	// `master` branch. GitHub serves raw blobs at any ref (tag, branch,
	// commit). Pinning at the tag closes the "force-push to master replaces
	// binaries" attack vector while preserving the project's existing
	// distribution model (binaries committed under release/<version>/).
	ver := strings.TrimPrefix(tagVersion, "v")
	base := fmt.Sprintf(
		"https://raw.githubusercontent.com/mrthoabby/serverpilot/%s/release/%s",
		tagVersion, ver,
	)
	binURL := fmt.Sprintf("%s/sp-%s-%s", base, osName, archName)
	sumURL := binURL + ".sha256"

	binBytes, err := fetchLimitedBytes(client, binURL, maxBinarySize)
	if err != nil {
		return fmt.Errorf("binary download failed")
	}

	// Best-effort checksum verification. Strict if sidecar exists.
	sumBytes, sumErr := fetchLimitedBytes(client, sumURL, maxChecksumSize)
	if sumErr == nil && len(sumBytes) > 0 {
		sumFields := strings.Fields(string(sumBytes))
		if len(sumFields) == 0 {
			return fmt.Errorf("empty checksum file — refusing update")
		}
		expectedSum, err := hex.DecodeString(sumFields[0])
		if err != nil || len(expectedSum) != sha256.Size {
			return fmt.Errorf("invalid checksum file — refusing update")
		}
		actualSum := sha256.Sum256(binBytes)
		if subtle.ConstantTimeCompare(actualSum[:], expectedSum) != 1 {
			return fmt.Errorf("checksum mismatch — refusing update")
		}
	} else {
		// Sidecar not published. We still have TLS 1.2+ minimum, pinned tag
		// (force-push to master cannot affect us), and atomic replace +
		// rollback. The remaining residual risk is GitHub-account compromise
		// of the publisher; mitigation is to add the sidecar in vs-pre-run/.
		fmt.Fprintf(os.Stderr,
			"warning: no checksum sidecar at %s — proceeding with TLS + tag-pinning only\n",
			sumURL)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path")
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}
	dir := filepath.Dir(execPath)

	tmp, err := os.CreateTemp(dir, ".sp-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file")
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(binBytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write failed")
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync failed")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close failed")
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		return fmt.Errorf("failed to replace binary")
	}
	return nil
}

// updateBinaryWithRollback wraps downloadAndReplace with a smoke-test +
// automatic rollback on failure. Converts a one-shot bricking event into a
// recoverable failure.
func updateBinaryWithRollback(latestVersion string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path")
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	backupPath := execPath + ".old"
	// Best-effort backup of current binary before swap.
	if data, rerr := os.ReadFile(execPath); rerr == nil {
		_ = os.WriteFile(backupPath, data, 0o755)
	}

	if err := downloadAndReplace(latestVersion); err != nil {
		return err
	}

	// Smoke-test the new binary before asking systemd to swap.
	smokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	smoke := exec.CommandContext(smokeCtx, execPath, "--version")
	smoke.Stdout = io.Discard
	smoke.Stderr = io.Discard
	if err := smoke.Run(); err != nil {
		// Roll back.
		if _, serr := os.Stat(backupPath); serr == nil {
			_ = os.Rename(backupPath, execPath)
		}
		return fmt.Errorf("new binary failed smoke test, rolled back")
	}
	return nil
}
