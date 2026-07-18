package trafficswitch

import (
	"fmt"

	"github.com/mrthoabby/serverpilot/internal/sites"
)

// PortSwitch maps an old published host port to the new color port.
type PortSwitch struct {
	OldPort int
	NewPort int
}

// RepointComposeProject switches nginx for sites linked to a compose project.
func RepointComposeProject(project string, switches []PortSwitch) error {
	siteList, err := sitesForComposeProject(project, switches)
	if err != nil {
		return err
	}
	for _, sw := range switches {
		if sw.OldPort <= 0 || sw.NewPort <= 0 || sw.OldPort == sw.NewPort {
			continue
		}
		for _, site := range siteList {
			if site.HostPort == sw.OldPort {
				if err := sites.RepointHostPort(site.ID, sw.NewPort); err != nil {
					return fmt.Errorf("blue-green nginx switch: %w", err)
				}
			}
		}
	}
	return nil
}

// RepointContainerSites switches all sites linked to a container to a new host port.
func RepointContainerSites(containerID, containerName string, newHostPort, fallbackOldPort int) error {
	siteList, err := sites.SitesForContainer(containerID, containerName)
	if err != nil {
		return err
	}
	if len(siteList) == 0 {
		return fmt.Errorf("no nginx sites linked to this container")
	}
	for _, site := range siteList {
		fromPort := site.HostPort
		if fromPort == 0 {
			fromPort = fallbackOldPort
		}
		if fromPort == newHostPort {
			continue
		}
		if err := sites.RepointHostPort(site.ID, newHostPort); err != nil {
			return err
		}
	}
	return nil
}

func sitesForComposeProject(project string, switches []PortSwitch) ([]sites.SiteRecord, error) {
	if recs, err := sites.SitesForComposeProject(project); err == nil && len(recs) > 0 {
		return recs, nil
	}
	portSet := make(map[int]struct{}, len(switches))
	for _, sw := range switches {
		if sw.OldPort > 0 {
			portSet[sw.OldPort] = struct{}{}
		}
	}
	all, err := sites.List()
	if err != nil {
		return nil, err
	}
	var out []sites.SiteRecord
	for _, s := range all {
		if _, ok := portSet[s.HostPort]; ok {
			out = append(out, s)
		}
	}
	return out, nil
}
