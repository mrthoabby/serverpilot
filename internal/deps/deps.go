package deps

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var dockerPaths = []string{"/usr/bin/docker", "/usr/local/bin/docker"}
var nginxPaths = []string{"/usr/sbin/nginx", "/usr/bin/nginx", "/usr/local/bin/nginx"}
var certbotPaths = []string{"/usr/bin/certbot", "/usr/local/bin/certbot", "/snap/bin/certbot"}

// findBinary searches for a binary in the given paths and returns the first match.
func findBinary(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// isInstalled checks if a binary exists at any of the known paths.
func isInstalled(paths []string) bool {
	return findBinary(paths) != ""
}

// distroID reads /etc/os-release and returns the lowercase ID value (e.g. "debian", "ubuntu").
func distroID() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"'`)
			return strings.ToLower(strings.TrimSpace(id))
		}
	}
	return "unknown"
}

// fixDockerAptSources scans /etc/apt/sources.list.d/ for Docker source files that
// reference the wrong Linux distribution and corrects them so apt-get update succeeds.
// Docker maintains separate repos per distro; mixing them (e.g. ubuntu on Debian) causes
// 404 errors. This is a no-op when no Docker source files are present.
func fixDockerAptSources() {
	id := distroID()
	if id == "unknown" || id == "ubuntu" {
		// No correction needed on Ubuntu, or when distro is undetectable.
		return
	}

	dir := "/etc/apt/sources.list.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// Distros whose repos are hosted under download.docker.com/linux/<distro>.
	// ubuntu and debian are the only two we fix automatically.
	knownWrong := []string{"ubuntu"}
	if id == "ubuntu" {
		knownWrong = []string{"debian"}
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only touch files that look like Docker source files.
		if !strings.Contains(strings.ToLower(name), "docker") {
			continue
		}

		path := filepath.Join(dir, name)
		// Hardening (CWE-22): canonicalise and refuse to follow a symlink at
		// the leaf. /etc/apt/sources.list.d is root-owned, but defense-in-depth
		// against any future change in directory ownership.
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Printf("[setup] WARNING: refusing to rewrite symlink %s\n", path)
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || filepath.Dir(resolved) != dir {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(raw)

		changed := false
		for _, wrong := range knownWrong {
			wrongToken := "download.docker.com/linux/" + wrong
			if strings.Contains(content, wrongToken) {
				rightToken := "download.docker.com/linux/" + id
				content = strings.ReplaceAll(content, wrongToken, rightToken)
				fmt.Printf("[setup] Fixed Docker apt source %s: replaced %q with %q\n",
					name, "linux/"+wrong, "linux/"+id)
				changed = true
			}
		}

		if changed {
			// Write corrected content with same permissions.
			info, _ := e.Info()
			mode := os.FileMode(0644)
			if info != nil {
				mode = info.Mode()
			}
			if werr := os.WriteFile(path, []byte(content), mode); werr != nil {
				fmt.Printf("[setup] WARNING: could not write fixed apt source %s: %v\n", name, werr)
			}
		}
	}
}

// CheckAndInstall checks if Docker and Nginx are installed.
// If not, it prompts the user and attempts to install them via apt-get.
func CheckAndInstall() error {
	if !isInstalled(dockerPaths) {
		fmt.Println("Docker is not installed.")
		if !promptInstall("Docker") {
			return fmt.Errorf("docker is required but not installed")
		}
		// Repair any stale Docker apt sources that point to the wrong distro
		// before running apt-get update — a mismatched repo (e.g. ubuntu on Debian)
		// causes apt-get update to fail with 404 even when docker.io is available
		// from the distribution's own repos.
		fixDockerAptSources()
		if err := installPackage("docker.io"); err != nil {
			return fmt.Errorf("failed to install Docker: %w", err)
		}
		fmt.Println("Docker installed successfully.")
	} else {
		fmt.Println("Docker: OK")
	}

	if !isInstalled(nginxPaths) {
		fmt.Println("Nginx is not installed.")
		if !promptInstall("Nginx") {
			return fmt.Errorf("nginx is required but not installed")
		}
		if err := installPackage("nginx"); err != nil {
			return fmt.Errorf("failed to install Nginx: %w", err)
		}
		fmt.Println("Nginx installed successfully.")
	} else {
		fmt.Println("Nginx: OK")
	}

	return nil
}

// Verify checks that Docker and Nginx are installed and returns an error if not.
func Verify() error {
	if !isInstalled(dockerPaths) {
		return fmt.Errorf("docker is not installed; run 'sp setup' first")
	}
	if !isInstalled(nginxPaths) {
		return fmt.Errorf("nginx is not installed; run 'sp setup' first")
	}
	return nil
}

// DockerPath returns the absolute path to the docker binary.
func DockerPath() (string, error) {
	p := findBinary(dockerPaths)
	if p == "" {
		return "", fmt.Errorf("docker binary not found")
	}
	return p, nil
}

// NginxPath returns the absolute path to the nginx binary.
func NginxPath() (string, error) {
	p := findBinary(nginxPaths)
	if p == "" {
		return "", fmt.Errorf("nginx binary not found")
	}
	return p, nil
}

// FindCertbot searches for certbot binary in common locations and PATH.
func FindCertbot() (string, error) {
	p := findBinary(certbotPaths)
	if p != "" {
		return p, nil
	}
	// Try PATH lookup as last resort.
	if p, err := exec.LookPath("certbot"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("certbot not found")
}

// IsCertbotInstalled checks if certbot is available.
func IsCertbotInstalled() bool {
	_, err := FindCertbot()
	return err == nil
}

// CheckAndInstallCertbot checks if certbot and the nginx plugin are installed.
// If not, it prompts the user and attempts to install them.
func CheckAndInstallCertbot() error {
	if IsCertbotInstalled() {
		fmt.Println("  Certbot: OK")
		return nil
	}

	fmt.Println("  Certbot is not installed.")
	if !promptInstall("certbot and python3-certbot-nginx") {
		return fmt.Errorf("certbot is required for SSL but not installed")
	}

	if err := installPackage("certbot"); err != nil {
		return fmt.Errorf("failed to install certbot: %w", err)
	}
	if err := installPackage("python3-certbot-nginx"); err != nil {
		return fmt.Errorf("failed to install python3-certbot-nginx: %w", err)
	}
	fmt.Println("  Certbot installed successfully.")
	return nil
}

// PromptYesNo asks a yes/no question and returns true for y/yes (exported for setup).
func PromptYesNo(prompt string) bool {
	return promptInstall(prompt)
}

func promptInstall(name string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Would you like to install %s? [y/N]: ", name)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// pkgNameRegex restricts apt package names to the characters Debian/Ubuntu
// itself allows. Refuses any leading "-" (which apt would parse as a flag,
// CWE-78 argument injection) or shell metacharacters.
var pkgNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_-]*$`)

func installPackage(pkg string) error {
	if !pkgNameRegex.MatchString(pkg) {
		return fmt.Errorf("invalid package name")
	}

	// DEBIAN_FRONTEND=noninteractive prevents apt from spawning interactive
	// dialogs (debconf/postfix) that would block the daemon installer.
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	updateCmd := exec.Command("/usr/bin/apt-get", "update", "-y")
	updateCmd.Env = env
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	// "--" stops option processing so a package name beginning with "-"
	// would still be impossible to inject (we already reject it via regex,
	// but defense-in-depth is cheap here).
	installCmd := exec.Command("/usr/bin/apt-get", "install", "-y", "--", pkg)
	installCmd.Env = env
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}

	return nil
}
