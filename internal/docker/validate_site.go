package docker

import (
	"fmt"
	"strconv"

	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

// ValidateSiteHostPort ensures the host port is published on the container or reserved for it.
func ValidateSiteHostPort(containerID string, hostPort, containerPort int) error {
	if _, err := GetContainerDetails(containerID); err != nil {
		return fmt.Errorf("container not found")
	}
	allPorts, err := InspectAllPortMappings(containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container ports")
	}
	hostStr := strconv.Itoa(hostPort)
	for _, p := range allPorts {
		if p.HostPort == hostStr && p.Protocol == "tcp" {
			return nil
		}
	}
	if containerPort > 0 {
		owner, err := PortReservationOwner(containerID, strconv.Itoa(containerPort), "tcp")
		if err == nil {
			if reserved, ok := portalloc.PortForOwner(owner); ok && reserved == hostPort {
				return nil
			}
		}
	}
	return fmt.Errorf("host port does not belong to container")
}
