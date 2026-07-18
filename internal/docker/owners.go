package docker

import (
	"fmt"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

// PortReservationOwner derives a stable registry owner for a container port.
// Compose-managed containers use project/service labels; standalone containers
// use the container name.
func PortReservationOwner(containerID, containerPort, protocol string) (string, error) {
	if strings.TrimSpace(containerPort) == "" {
		return "", fmt.Errorf("container port required")
	}
	if protocol == "" {
		protocol = "tcp"
	}
	runtime, err := inspectRuntime(containerID)
	if err != nil {
		return "", err
	}
	name := strings.TrimPrefix(runtime.Name, "/")
	if name == "" {
		name = "container"
	}
	if IsComposeContainer(runtime.Config.Labels) {
		meta := ParseComposeLabels(runtime.Config.Labels)
		if meta.Project == "" || meta.Service == "" {
			return "", fmt.Errorf("compose container is missing project or service labels")
		}
		return portalloc.ComposeStableOwner(meta.Project, meta.Service, containerPort, protocol), nil
	}
	return portalloc.DockerOwner(name, containerPort, protocol), nil
}
