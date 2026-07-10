package deps

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// composePluginVersion pins the GitHub release used when apt cannot provide
// docker-compose-plugin (common with docker.io from Debian/Ubuntu main repos).
const composePluginVersion = "v2.32.4"

// InstallLogger receives human-readable install progress lines.
type InstallLogger func(string)

// InstallPackageArgv runs apt-get update, then executes a fixed apt-get install argv.
func InstallPackageArgv(argv []string, log InstallLogger) error {
	if log == nil {
		log = func(string) {}
	}
	if len(argv) < 2 || argv[0] != "/usr/bin/apt-get" || argv[1] != "install" {
		return fmt.Errorf("invalid install argv")
	}
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	log("Running apt-get update...")
	updateCmd := exec.Command("/usr/bin/apt-get", "update", "-y")
	updateCmd.Env = env
	if err := streamCommand(updateCmd, log); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	log("Running: " + strings.Join(argv, " "))
	installCmd := exec.Command(argv[0], argv[1:]...)
	installCmd.Env = env
	if err := streamCommand(installCmd, log); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}
	return nil
}

// InstallComposePlugin ensures `docker compose` works. It tries apt first, then
// installs the official Compose v2 CLI plugin binary into standard Docker paths.
func InstallComposePlugin(log InstallLogger) error {
	if log == nil {
		log = func(string) {}
	}
	if ComposeAvailable() {
		log("Docker Compose is already available.")
		return nil
	}
	if !DockerInstalled() {
		return fmt.Errorf("docker must be installed before Docker Compose")
	}

	pkg := ComposePluginPackageForDistro()
	if pkg == "" {
		return fmt.Errorf("docker compose plugin is not available for this distribution")
	}

	log("Refreshing apt sources for Docker packages...")
	fixDockerAptSources()

	log("Trying apt install " + pkg + "...")
	if err := installPackageLogged(pkg, log); err != nil {
		log("apt install failed: " + err.Error())
		log("Falling back to official Compose CLI plugin binary...")
		if err := installComposePluginBinary(log); err != nil {
			return err
		}
	}

	if !ComposeAvailable() {
		return fmt.Errorf("docker compose still unavailable after installation")
	}
	ver, _ := ComposeVersion()
	if ver != "" {
		log("Docker Compose ready (" + ver + ").")
	} else {
		log("Docker Compose ready.")
	}
	return nil
}

func installPackageLogged(pkg string, log InstallLogger) error {
	if !pkgNameRegex.MatchString(pkg) {
		return fmt.Errorf("invalid package name")
	}
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	log("Running apt-get update...")
	updateCmd := exec.Command("/usr/bin/apt-get", "update", "-y")
	updateCmd.Env = env
	if err := streamCommand(updateCmd, log); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	log("Running apt-get install " + pkg + "...")
	installCmd := exec.Command("/usr/bin/apt-get", "install", "-y", "--", pkg)
	installCmd.Env = env
	if err := streamCommand(installCmd, log); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}
	return nil
}

func installComposePluginBinary(log InstallLogger) error {
	arch, err := composePluginArch()
	if err != nil {
		return err
	}
	url := fmt.Sprintf(
		"https://github.com/docker/compose/releases/download/%s/docker-compose-linux-%s",
		composePluginVersion,
		arch,
	)

	dest, err := composePluginBinaryPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("cannot create compose plugin directory")
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".docker-compose-download-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file for compose download")
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()

	log("Downloading Compose " + composePluginVersion + " (" + arch + ")...")
	if err := downloadFile(url, tmpPath, log); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("cannot chmod compose plugin binary")
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("cannot install compose plugin binary")
	}
	log("Installed compose plugin at " + dest)
	return nil
}

func composePluginBinaryPath() (string, error) {
	candidates := []string{
		"/usr/libexec/docker/cli-plugins/docker-compose",
		"/usr/local/lib/docker/cli-plugins/docker-compose",
	}
	for _, path := range candidates {
		if _, err := os.Stat(filepath.Dir(path)); err == nil {
			return path, nil
		}
	}
	return candidates[len(candidates)-1], nil
}

func composePluginArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	case "arm":
		return "armv7", nil
	default:
		return "", fmt.Errorf("unsupported architecture for compose plugin: %s", runtime.GOARCH)
	}
}

func downloadFile(url, dest string, log InstallLogger) error {
	if curl, err := exec.LookPath("curl"); err == nil {
		cmd := exec.Command(curl, "-fSL", url, "-o", dest)
		return streamCommand(cmd, log)
	}
	if wget, err := exec.LookPath("wget"); err == nil {
		cmd := exec.Command(wget, "-q", "-O", dest, url)
		return streamCommand(cmd, log)
	}
	return fmt.Errorf("curl or wget is required to download the compose plugin")
}

func streamCommand(cmd *exec.Cmd, log InstallLogger) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := readLines(stdout, log); err != nil {
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

func readLines(r io.Reader, log InstallLogger) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			log(line)
		}
	}
	return scanner.Err()
}
