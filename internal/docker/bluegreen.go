package docker

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deployhealth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/trafficswitch"
)

const (
	bgDefaultDrain      = 10 * time.Second
	bgDefaultHealthWait = 60 * time.Second
	bgColorBlue         = "blue"
	bgColorGreen        = "green"
)

// BlueGreenRequest describes a standalone container blue-green release.
type BlueGreenRequest struct {
	Container     string
	Image         string
	HealthURL     string
	HealthTimeout time.Duration
	Drain         time.Duration
}

// ReleaseBlueGreen starts a parallel color container, switches nginx, and removes the old one.
func ReleaseBlueGreen(req BlueGreenRequest) error {
	return releaseBlueGreen(req, func(string) {})
}

// ReleaseBlueGreenProgress is like ReleaseBlueGreen with progress callbacks.
func ReleaseBlueGreenProgress(req BlueGreenRequest, progress func(string)) error {
	return releaseBlueGreen(req, progress)
}

func releaseBlueGreen(req BlueGreenRequest, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	runtime, err := inspectRuntime(req.Container)
	if err != nil {
		return err
	}
	parentName := strings.TrimPrefix(runtime.Name, "/")
	if IsComposeContainer(runtime.Config.Labels) {
		return fmt.Errorf("compose-managed containers must use sp compose release --strategy blue-green")
	}
	if hasExclusiveMounts(runtime) {
		return fmt.Errorf("container has persistent mounts — use rolling update instead")
	}

	containerPort, protocol, oldHostPort, err := primaryPublishedTCP(runtime)
	if err != nil {
		return err
	}

	baseName := stripColorSuffix(parentName)
	currentColor := colorFromName(parentName)
	targetColor := oppositeColor(currentColor)
	targetName := colorContainerName(baseName, targetColor)

	owner := portalloc.DockerColorOwner(baseName, targetColor, containerPort, protocol)
	reserve, err := portalloc.ReserveOwnerWithMeta(owner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		return err
	}
	hostPort := reserve.Port
	cleanupPort := func() {
		if reserve.Created {
			_ = portalloc.ReleaseOwner(owner)
		}
	}

	image := strings.TrimSpace(req.Image)
	if image == "" {
		image = runtime.Config.Image
		if image == "" {
			image = runtime.Image
		}
	}
	progress("Starting " + targetColor + " container " + targetName + "...")
	if err := runReplacement(runtime, targetName, image, hostPort, containerPort, protocol); err != nil {
		cleanupPort()
		return err
	}
	cleanupContainer := func() { _ = removeContainer(targetName, true) }

	healthTimeout := req.HealthTimeout
	if healthTimeout <= 0 {
		healthTimeout = bgDefaultHealthWait
	}
	if err := deployhealth.WaitHealthy(deployhealth.Options{
		ContainerName: targetName,
		HostPort:      hostPort,
		HealthURL:     req.HealthURL,
		Timeout:       healthTimeout,
	}); err != nil {
		cleanupContainer()
		cleanupPort()
		return fmt.Errorf("blue-green health check failed: %w", err)
	}

	if err := trafficswitch.RepointContainerSites(runtime.ID, parentName, hostPort, oldHostPort); err != nil {
		cleanupContainer()
		cleanupPort()
		return err
	}

	drain := req.Drain
	if drain <= 0 {
		drain = bgDefaultDrain
	}
	if drain > 0 {
		progress(fmt.Sprintf("Draining connections for %s...", drain))
		time.Sleep(drain)
	}

	progress("Removing previous container...")
	if err := removeContainer(parentName, true); err != nil {
		return err
	}
	if currentColor != "" {
		_ = portalloc.ReleaseOwner(portalloc.DockerColorOwner(baseName, currentColor, containerPort, protocol))
	}
	progress("Blue-green release complete — active color is now " + targetColor + ".")
	return nil
}

func primaryPublishedTCP(runtime containerRuntimeInspect) (containerPort, protocol string, hostPort int, err error) {
	for key, bindings := range runtime.NetworkSettings.Ports {
		parts := strings.Split(key, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		if proto != "tcp" {
			continue
		}
		for _, b := range bindings {
			if b.HostPort == "" {
				continue
			}
			hp, convErr := strconv.Atoi(b.HostPort)
			if convErr != nil {
				continue
			}
			return cPort, proto, hp, nil
		}
	}
	return "", "", 0, fmt.Errorf("container has no published TCP port")
}

func hasExclusiveMounts(runtime containerRuntimeInspect) bool {
	for _, m := range runtime.Mounts {
		if m.Destination == "" {
			continue
		}
		if m.Type == "volume" || m.Type == "bind" {
			return true
		}
	}
	return false
}

func runReplacement(runtime containerRuntimeInspect, name, image string, hostPort int, containerPort, protocol string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := buildBlueGreenRunArgs(runtime, name, image, hostPort, containerPort, protocol)
	if _, err := exec.Command(dockerBin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run replacement container")
	}
	return nil
}

func buildBlueGreenRunArgs(runtime containerRuntimeInspect, name, image string, hostPort int, containerPort, protocol string) []string {
	args := []string{"run", "-d", "--name", name}
	if runtime.Config.User != "" {
		args = append(args, "--user", runtime.Config.User)
	}
	if runtime.Config.WorkingDir != "" {
		args = append(args, "--workdir", runtime.Config.WorkingDir)
	}
	if runtime.HostConfig.RestartPolicy.Name != "" && runtime.HostConfig.RestartPolicy.Name != "no" {
		restart := runtime.HostConfig.RestartPolicy.Name
		if restart == "on-failure" && runtime.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			restart += ":" + strconv.Itoa(runtime.HostConfig.RestartPolicy.MaximumRetryCount)
		}
		args = append(args, "--restart", restart)
	}
	if runtime.HostConfig.NetworkMode != "" && runtime.HostConfig.NetworkMode != "default" && runtime.HostConfig.NetworkMode != "bridge" {
		args = append(args, "--network", runtime.HostConfig.NetworkMode)
	}
	for k, v := range runtime.Config.Labels {
		args = append(args, "--label", k+"="+v)
	}
	for _, item := range runtime.Config.Env {
		args = append(args, "-e", item)
	}
	if networkModeAllowsPortPublish(runtime.HostConfig.NetworkMode) {
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:%s/%s", hostPort, containerPort, protocol))
	}
	for _, m := range runtime.Mounts {
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		source := m.Source
		if m.Type == "volume" && m.Name != "" {
			source = m.Name
		}
		if source == "" || m.Destination == "" {
			continue
		}
		args = append(args, "-v", source+":"+m.Destination+":"+mode)
	}
	if len(runtime.Config.Entrypoint) == 1 {
		args = append(args, "--entrypoint", runtime.Config.Entrypoint[0])
	}
	args = append(args, image)
	args = append(args, runtime.Config.Cmd...)
	return args
}

func removeContainer(name string, force bool) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := []string{"rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)
	return exec.Command(dockerBin, args...).Run()
}

func colorContainerName(base, color string) string {
	return base + "__" + color
}

func stripColorSuffix(name string) string {
	if idx := strings.LastIndex(name, "__"); idx > 0 {
		suffix := name[idx+2:]
		if suffix == bgColorGreen || suffix == bgColorBlue {
			return name[:idx]
		}
	}
	return name
}

func colorFromName(name string) string {
	if strings.HasSuffix(name, "__"+bgColorGreen) {
		return bgColorGreen
	}
	if strings.HasSuffix(name, "__"+bgColorBlue) {
		return bgColorBlue
	}
	return bgColorBlue
}

func oppositeColor(color string) string {
	if color == bgColorGreen {
		return bgColorBlue
	}
	return bgColorGreen
}
