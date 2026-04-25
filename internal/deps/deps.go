package deps

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

// CheckAndInstall checks if Docker and Nginx are installed.
// If not, it prompts the user and attempts to install them via apt-get.
func CheckAndInstall() error {
	if !isInstalled(dockerPaths) {
		fmt.Println("Docker is not installed.")
		if !promptInstall("Docker") {
			return fmt.Errorf("docker is required but not installed")
		}
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

func installPackage(pkg string) error {
	updateCmd := exec.Command("/usr/bin/apt-get", "update", "-y")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	installCmd := exec.Command("/usr/bin/apt-get", "install", "-y", pkg)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}

	return nil
}
