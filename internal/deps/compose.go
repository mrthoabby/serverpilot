package deps

import (
	"fmt"
	"os/exec"
	"strings"
)

// ComposePluginPackage is the Debian/Ubuntu package that provides `docker compose`.
const ComposePluginPackage = "docker-compose-plugin"

// ComposeAvailable reports whether Docker Compose v2 is usable.
func ComposeAvailable() bool {
	_, err := ComposeVersion()
	return err == nil
}

// ComposeVersion returns the trimmed output of `docker compose version`.
func ComposeVersion() (string, error) {
	dockerBin, err := DockerPath()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(dockerBin, "compose", "version", "--short")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker compose not available")
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", fmt.Errorf("docker compose not available")
	}
	return version, nil
}

// ComposePluginPackageForDistro returns the apt package name for Compose v2 on
// the current distro, or empty when no supported package is known.
func ComposePluginPackageForDistro() string {
	switch distroID() {
	case "debian", "ubuntu":
		return ComposePluginPackage
	default:
		return ""
	}
}

// CheckAndInstallComposePlugin installs the Compose v2 plugin when Docker is
// present but `docker compose` is missing.
func CheckAndInstallComposePlugin() error {
	if ComposeAvailable() {
		fmt.Println("  Docker Compose: OK")
		return nil
	}

	pkg := ComposePluginPackageForDistro()
	if pkg == "" {
		return fmt.Errorf("docker compose plugin is not available for this distribution")
	}

	fmt.Println("  Docker Compose plugin is not installed.")
	if !promptInstall(pkg) {
		return fmt.Errorf("docker compose is required but not installed")
	}
	if err := installPackage(pkg); err != nil {
		return fmt.Errorf("failed to install %s: %w", pkg, err)
	}
	if !ComposeAvailable() {
		return fmt.Errorf("docker compose still unavailable after installing %s", pkg)
	}
	fmt.Println("  Docker Compose installed successfully.")
	return nil
}
