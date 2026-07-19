package docker

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/labels"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

var containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// DeleteContainerOptions controls container removal from the dashboard.
type DeleteContainerOptions struct {
	IDOrName    string
	RemoveImage bool
}

// DeleteContainerResult reports what was removed.
type DeleteContainerResult struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ImageRemoved  bool   `json:"image_removed"`
	ImageID       string `json:"image_id,omitempty"`
	ImageWarning  string `json:"image_warning,omitempty"`
}

// ValidateContainerRef accepts a hex container ID or a Docker container name.
func ValidateContainerRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("container is required")
	}
	if validateContainerID(ref) == nil {
		return nil
	}
	if containerNameRegex.MatchString(ref) {
		return nil
	}
	return fmt.Errorf("invalid container reference")
}

// DeleteContainer stops and removes a standalone Docker container. Compose-managed
// containers must be removed with compose down instead.
func DeleteContainer(opts DeleteContainerOptions) (DeleteContainerResult, error) {
	ref := strings.TrimSpace(opts.IDOrName)
	if err := ValidateContainerRef(ref); err != nil {
		return DeleteContainerResult{}, err
	}

	runtime, err := inspectRuntime(ref)
	if err != nil {
		return DeleteContainerResult{}, fmt.Errorf("container not found")
	}
	name := strings.TrimPrefix(runtime.Name, "/")
	if name == "" {
		return DeleteContainerResult{}, fmt.Errorf("container has no name")
	}
	if IsComposeContainer(runtime.Config.Labels) {
		return DeleteContainerResult{}, fmt.Errorf("compose containers must be removed with compose down")
	}

	releaseContainerPortOwners(name, runtime)

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return DeleteContainerResult{}, err
	}
	if out, err := exec.Command(dockerBin, "rm", "-f", "--", ref).CombinedOutput(); err != nil {
		return DeleteContainerResult{}, fmt.Errorf("failed to remove container: %s", strings.TrimSpace(string(out)))
	}

	_ = labels.Remove(name)

	result := DeleteContainerResult{
		ContainerID:   runtime.ID,
		ContainerName: name,
	}
	imageID := strings.TrimSpace(runtime.Image)
	if opts.RemoveImage && imageID != "" {
		result.ImageID = imageID
		if err := RemoveImage(imageID); err != nil {
			result.ImageWarning = "container removed but image could not be deleted"
		} else {
			result.ImageRemoved = true
		}
	}
	return result, nil
}

func releaseContainerPortOwners(name string, runtime containerRuntimeInspect) {
	baseName := stripContainerColorSuffix(name)
	for containerPort, bindings := range runtime.NetworkSettings.Ports {
		parts := strings.Split(containerPort, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		for _, binding := range bindings {
			if binding.HostPort == "" {
				continue
			}
			_ = portalloc.ReleaseOwner(portalloc.DockerOwner(name, cPort, proto))
			_ = portalloc.ReleaseOwner(portalloc.DockerOwner(baseName, cPort, proto))
			_ = portalloc.ReleaseOwner(portalloc.DockerColorOwner(baseName, "green", cPort, proto))
			_ = portalloc.ReleaseOwner(portalloc.DockerColorOwner(baseName, "blue", cPort, proto))
		}
	}
	portalloc.ReleaseOwnersByPrefix("docker:" + name + ":")
	if baseName != name {
		portalloc.ReleaseOwnersByPrefix("docker:" + baseName + ":")
	}
}

func stripContainerColorSuffix(name string) string {
	if idx := strings.LastIndex(name, "__"); idx > 0 {
		suffix := name[idx+2:]
		if suffix == "green" || suffix == "blue" {
			return name[:idx]
		}
	}
	return name
}
