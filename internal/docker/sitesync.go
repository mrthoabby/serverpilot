package docker

import (
	"fmt"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/sites"
)

// SyncLinkedContainerSites repoints every site linked to a container so nginx
// proxies to the container's current published TCP host port. It also refreshes
// the stored container ID after docker run recreates replace the container.
func SyncLinkedContainerSites(containerName, containerID, containerPort string) (int, error) {
	containerName = strings.TrimSpace(containerName)
	containerID = strings.TrimSpace(containerID)
	containerPort = strings.TrimSpace(containerPort)
	if containerPort == "" {
		containerPort = "3000"
	}
	if containerName == "" && containerID == "" {
		return 0, fmt.Errorf("container name or id is required")
	}

	hostPort, resolvedID, err := PublishedTCPHostPort(containerID, containerName, containerPort)
	if err != nil {
		return 0, err
	}
	if containerID == "" {
		containerID = resolvedID
	}

	recs, err := sites.SitesForContainer(containerID, containerName)
	if err != nil {
		return 0, err
	}
	if len(recs) == 0 {
		return hostPort, nil
	}

	for _, rec := range recs {
		if rec.HostPort != hostPort {
			if err := sites.RepointHostPort(rec.ID, hostPort); err != nil {
				return 0, err
			}
		}
		if containerID != "" && rec.ContainerID != containerID {
			updated, ok, err := sites.GetByID(rec.ID)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			updated.ContainerID = containerID
			if containerName != "" {
				updated.ContainerName = containerName
			}
			updated.UpdatedAt = time.Now().UTC()
			if err := sites.Upsert(updated); err != nil {
				return 0, err
			}
		}
	}
	return hostPort, nil
}
