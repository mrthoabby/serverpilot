package mapper

import (
	"fmt"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/nginx"
)

// Mapping represents a relationship between a Docker container and an Nginx site.
type Mapping struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ContainerPort string `json:"container_port"`
	NginxDomain   string `json:"nginx_domain"`
	NginxConfPath string `json:"nginx_config_path"`
	SSLEnabled    bool   `json:"ssl_enabled"`
	SSLAutoRenew  bool   `json:"ssl_auto_renew"`
}

// MappingsResult holds all mapping data computed in a single pass.
// Using a single function avoids shelling out to docker/nginx multiple times.
type MappingsResult struct {
	Mapped             []Mapping          `json:"mapped"`
	UnmappedContainers []docker.Container `json:"unmappedContainers"`
	OrphanedSites      []nginx.Site       `json:"orphanedSites"`
}

// ComputeAllMappings fetches containers and sites ONCE, then computes
// mapped, unmapped, and orphaned in a single pass. This replaces three
// separate functions that each shelled out independently — previously
// /api/mappings triggered 4× docker ps + 3× nginx ListSites.
func ComputeAllMappings() (*MappingsResult, error) {
	containers, err := docker.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	sites, err := nginx.ListSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list sites: %w", err)
	}

	result := &MappingsResult{}

	// --- Mapped containers ---
	mappedIDs := make(map[string]bool)
	for _, container := range containers {
		for _, port := range container.Ports {
			for _, site := range sites {
				if site.ProxyPass == "" {
					continue
				}
				if matchesProxyPass(site.ProxyPass, port.HostPort) {
					result.Mapped = append(result.Mapped, Mapping{
						ContainerID:   container.ID,
						ContainerName: container.Name,
						ContainerPort: port.HostPort,
						NginxDomain:   site.Domain,
						NginxConfPath: site.ConfigPath,
						SSLEnabled:    site.SSLEnabled,
						SSLAutoRenew:  site.SSLAutoRnw,
					})
					mappedIDs[container.ID] = true
				}
			}
		}
	}

	// --- Unmapped containers (no nginx site) ---
	for _, c := range containers {
		if !mappedIDs[c.ID] {
			result.UnmappedContainers = append(result.UnmappedContainers, c)
		}
	}

	// --- Orphaned sites (proxy_pass points to port with no running container) ---
	activePorts := make(map[string]bool, len(containers)*2)
	for _, c := range containers {
		for _, p := range c.Ports {
			activePorts[p.HostPort] = true
		}
	}
	for _, site := range sites {
		if site.ProxyPass == "" {
			continue
		}
		port := extractPortFromProxyPass(site.ProxyPass)
		if port != "" && !activePorts[port] {
			result.OrphanedSites = append(result.OrphanedSites, site)
		}
	}

	return result, nil
}

// MapContainersToSites cross-references docker container ports with nginx proxy_pass
// directives to find containers that have corresponding nginx sites.
func MapContainersToSites() ([]Mapping, error) {
	r, err := ComputeAllMappings()
	if err != nil {
		return nil, err
	}
	return r.Mapped, nil
}

// matchesProxyPass checks if a proxy_pass URL targets the given port.
func matchesProxyPass(proxyPass, hostPort string) bool {
	if hostPort == "" {
		return false
	}
	// Common patterns: http://localhost:PORT, http://127.0.0.1:PORT
	return strings.Contains(proxyPass, ":"+hostPort)
}

// extractPortFromProxyPass extracts the port number from a proxy_pass URL.
func extractPortFromProxyPass(proxyPass string) string {
	// Look for the pattern :<port> at the end or before a path.
	idx := strings.LastIndex(proxyPass, ":")
	if idx == -1 {
		return ""
	}
	rest := proxyPass[idx+1:]
	// Strip trailing path.
	if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
		rest = rest[:slashIdx]
	}
	rest = strings.TrimRight(rest, ";")
	rest = strings.TrimSpace(rest)
	// Validate it looks like a port number.
	for _, c := range rest {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return rest
}
