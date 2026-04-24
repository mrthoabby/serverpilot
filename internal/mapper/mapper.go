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

// MapContainersToSites cross-references docker container ports with nginx proxy_pass
// directives to find containers that have corresponding nginx sites.
func MapContainersToSites() ([]Mapping, error) {
	containers, err := docker.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	sites, err := nginx.ListSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list sites: %w", err)
	}

	var mappings []Mapping

	for _, container := range containers {
		for _, port := range container.Ports {
			for _, site := range sites {
				if site.ProxyPass == "" {
					continue
				}
				// Match if the proxy_pass URL contains the host port.
				if matchesProxyPass(site.ProxyPass, port.HostPort) {
					mapping := Mapping{
						ContainerID:   container.ID,
						ContainerName: container.Name,
						ContainerPort: port.HostPort,
						NginxDomain:   site.Domain,
						NginxConfPath: site.ConfigPath,
						SSLEnabled:    site.SSLEnabled,
						SSLAutoRenew:  site.SSLAutoRnw,
					}
					mappings = append(mappings, mapping)
				}
			}
		}
	}

	return mappings, nil
}

// GetUnmappedContainers returns containers that do not have an nginx site configured.
func GetUnmappedContainers() ([]docker.Container, error) {
	mappings, err := MapContainersToSites()
	if err != nil {
		return nil, err
	}

	containers, err := docker.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	mappedIDs := make(map[string]bool)
	for _, m := range mappings {
		mappedIDs[m.ContainerID] = true
	}

	var unmapped []docker.Container
	for _, c := range containers {
		if !mappedIDs[c.ID] {
			unmapped = append(unmapped, c)
		}
	}

	return unmapped, nil
}

// GetOrphanedSites returns nginx sites whose proxy_pass points to ports
// not exposed by any running container.
func GetOrphanedSites() ([]nginx.Site, error) {
	containers, err := docker.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	sites, err := nginx.ListSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list sites: %w", err)
	}

	// Collect all host ports from running containers.
	activePorts := make(map[string]bool)
	for _, c := range containers {
		for _, p := range c.Ports {
			activePorts[p.HostPort] = true
		}
	}

	var orphaned []nginx.Site
	for _, site := range sites {
		if site.ProxyPass == "" {
			continue
		}
		port := extractPortFromProxyPass(site.ProxyPass)
		if port != "" && !activePorts[port] {
			orphaned = append(orphaned, site)
		}
	}

	return orphaned, nil
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
