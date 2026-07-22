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

// UpdateSiteMappingInput updates container linkage and nginx host port for a managed site.
type UpdateSiteMappingInput struct {
	SiteID        string
	ConfigName    string
	Domain        string
	ContainerID   string
	ContainerName string
	HostPort      int
	ContainerPort int
}

// UpdateSiteMapping repoints nginx when needed and updates the site registry record.
func UpdateSiteMapping(in UpdateSiteMappingInput) (sites.SiteRecord, error) {
	rec, err := sites.ResolveManagedSite(in.SiteID, in.ConfigName, in.Domain)
	if err != nil {
		return sites.SiteRecord{}, err
	}
	if in.HostPort < 1 || in.HostPort > 65535 {
		return sites.SiteRecord{}, fmt.Errorf("invalid host port")
	}
	if in.ContainerPort < 1 || in.ContainerPort > 65535 {
		return sites.SiteRecord{}, fmt.Errorf("invalid container port")
	}

	containerID := strings.TrimSpace(in.ContainerID)
	containerName := strings.TrimSpace(in.ContainerName)
	if containerID == "" && containerName != "" {
		containers, listErr := ListContainers()
		if listErr == nil {
			for _, c := range containers {
				if c.Name == containerName {
					containerID = c.ID
					break
				}
			}
		}
	}
	if containerID != "" {
		if err := ValidateSiteHostPort(containerID, in.HostPort, in.ContainerPort); err != nil {
			return sites.SiteRecord{}, err
		}
	}

	if rec.HostPort != in.HostPort {
		if err := sites.RepointHostPort(rec.ID, in.HostPort); err != nil {
			return sites.SiteRecord{}, err
		}
	}

	updated, ok, err := sites.GetByID(rec.ID)
	if err != nil {
		return sites.SiteRecord{}, err
	}
	if !ok {
		return sites.SiteRecord{}, fmt.Errorf("site not found")
	}
	if containerID != "" {
		updated.ContainerID = containerID
	}
	if containerName != "" {
		updated.ContainerName = containerName
	}
	updated.HostPort = in.HostPort
	updated.ContainerPort = in.ContainerPort
	updated.UpdatedAt = time.Now().UTC()
	if err := sites.Upsert(updated); err != nil {
		return sites.SiteRecord{}, err
	}
	return updated, nil
}
