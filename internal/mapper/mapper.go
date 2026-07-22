package mapper

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

// Mapping represents a relationship between a Docker container and an Nginx site.
type Mapping struct {
	SiteID         string `json:"site_id,omitempty"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	ContainerPort  string `json:"container_port"`
	HostPort       string `json:"host_port"`
	NginxDomain    string `json:"nginx_domain"`
	ConfigName     string `json:"config_name,omitempty"`
	NginxConfPath  string `json:"nginx_config_path"`
	SSLEnabled     bool   `json:"ssl_enabled"`
	SSLAutoRenew   bool   `json:"ssl_auto_renew"`
	Template       string `json:"template,omitempty"`
	Orphaned       bool   `json:"orphaned,omitempty"`
	RedirectActive bool   `json:"redirect_active,omitempty"`
}

// ComputeOptions tunes mapping inference (e.g. dashboard site detection).
type ComputeOptions struct {
	DashboardDomain string
	DashboardPort   int
}

// MappingsResult holds all mapping data computed in a single pass.
type MappingsResult struct {
	Mapped              []Mapping          `json:"mapped"`
	UnmappedContainers  []docker.Container `json:"unmappedContainers"`
	OrphanedSites       []nginx.Site       `json:"orphanedSites"`
	DashboardSites      []nginx.Site       `json:"dashboardSites"`
	StandaloneRedirects []nginx.Site       `json:"standalone_redirects"`
	UnassignedSites     []nginx.Site       `json:"unassigned_sites"`
}

// ComputeAllMappings fetches containers and sites once, then computes associations.
func ComputeAllMappings() (*MappingsResult, error) {
	return ComputeAllMappingsWith(ComputeOptions{})
}

// ComputeAllMappingsWith is like ComputeAllMappings but accepts dashboard hints so
// the ServerPilot panel vhost is not classified as an orphaned site.
func ComputeAllMappingsWith(opts ComputeOptions) (*MappingsResult, error) {
	containers, err := docker.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	nginxSites, err := nginx.ListSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list sites: %w", err)
	}

	records, err := sites.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list site registry: %w", err)
	}

	result := &MappingsResult{}
	mappedIDs := make(map[string]bool)
	mappedConfigNames := make(map[string]bool)

	activePorts := make(map[string]bool, len(containers)*2)
	containerByID := make(map[string]docker.Container, len(containers))
	containerByName := make(map[string]docker.Container, len(containers))
	for _, c := range containers {
		containerByID[c.ID] = c
		containerByName[c.Name] = c
		for _, p := range c.Ports {
			if p.HostPort != "" {
				activePorts[p.HostPort] = true
			}
		}
	}

	siteByDomain := make(map[string]nginx.Site, len(nginxSites))
	for _, s := range nginxSites {
		siteByDomain[s.Domain] = s
		if s.ConfigPath != "" {
			name := s.ConfigPath[strings.LastIndex(s.ConfigPath, "/")+1:]
			siteByDomain[name] = s
		}
	}

	for _, rec := range records {
		site, ok := siteByDomain[rec.ConfigName]
		if !ok {
			site, ok = siteByDomain[rec.Domain]
		}
		m := mappingFromRecord(rec, site)
		if rec.ContainerID != "" {
			if c, ok := containerByID[rec.ContainerID]; ok {
				m.ContainerName = c.Name
				mappedIDs[c.ID] = true
			} else if rec.ContainerName != "" {
				m.ContainerName = rec.ContainerName
				if c, ok := containerByName[rec.ContainerName]; ok {
					m.ContainerID = c.ID
					mappedIDs[c.ID] = true
				} else {
					m.Orphaned = true
				}
			} else {
				m.Orphaned = true
			}
		} else if rec.ContainerName != "" {
			m.ContainerName = rec.ContainerName
			if c, ok := containerByName[rec.ContainerName]; ok {
				m.ContainerID = c.ID
				mappedIDs[c.ID] = true
			} else {
				m.Orphaned = true
			}
		}
		if m.HostPort != "" && !activePorts[m.HostPort] {
			m.Orphaned = true
		}
		result.Mapped = append(result.Mapped, m)
		mappedConfigNames[rec.ConfigName] = true
	}

	// Legacy inference for configs not in registry.
	for _, site := range nginxSites {
		configName := site.ConfigPath
		if idx := strings.LastIndex(configName, "/"); idx >= 0 {
			configName = configName[idx+1:]
		}
		if mappedConfigNames[configName] {
			continue
		}
		if site.RedirectTarget != "" && site.ProxyPass == "" {
			result.StandaloneRedirects = append(result.StandaloneRedirects, site)
			continue
		}
		port, _ := extractPortFromProxyPass(site.ProxyPass)
		attached := false
		for _, container := range containers {
			for _, p := range container.Ports {
				if port != "" && p.HostPort == port {
					meta := templates.ParseMetadataFromConfig(readConfigSafe(configName))
					result.Mapped = append(result.Mapped, Mapping{
						ContainerID:   container.ID,
						ContainerName: container.Name,
						ContainerPort: p.ContainerPort,
						HostPort:      p.HostPort,
						NginxDomain:   site.Domain,
						NginxConfPath: site.ConfigPath,
						SSLEnabled:    site.SSLEnabled,
						SSLAutoRenew:  site.SSLAutoRnw,
						Template:      meta.Template,
					})
					mappedIDs[container.ID] = true
					attached = true
				}
			}
		}
		if !attached {
			configName := configBaseName(site)
			if isDashboardSite(site, readConfigSafe(configName), opts) {
				result.DashboardSites = append(result.DashboardSites, site)
				continue
			}
			if port != "" && !activePorts[port] {
				result.OrphanedSites = append(result.OrphanedSites, site)
			} else {
				result.UnassignedSites = append(result.UnassignedSites, site)
			}
		}
	}

	for _, c := range containers {
		if !mappedIDs[c.ID] {
			result.UnmappedContainers = append(result.UnmappedContainers, c)
		}
	}

	return result, nil
}

func mappingFromRecord(rec sites.SiteRecord, site nginx.Site) Mapping {
	m := Mapping{
		SiteID:         rec.ID,
		ContainerID:    rec.ContainerID,
		ContainerName:  rec.ContainerName,
		NginxDomain:    rec.Domain,
		ConfigName:     rec.ConfigName,
		Template:       string(rec.Template),
		RedirectActive: rec.State == sites.StateRedirectOverlay,
	}
	if rec.HostPort > 0 {
		m.HostPort = strconv.Itoa(rec.HostPort)
		m.ContainerPort = m.HostPort
	}
	if rec.ContainerPort > 0 {
		m.ContainerPort = strconv.Itoa(rec.ContainerPort)
	}
	if site.ConfigPath != "" {
		m.NginxConfPath = site.ConfigPath
		m.SSLEnabled = site.SSLEnabled
		m.SSLAutoRenew = site.SSLAutoRnw
		if m.ConfigName == "" {
			m.ConfigName = configBaseName(site)
		}
	}
	return m
}

func configBaseName(site nginx.Site) string {
	configName := site.ConfigPath
	if idx := strings.LastIndex(configName, "/"); idx >= 0 {
		configName = configName[idx+1:]
	}
	return configName
}

// isDashboardSite reports nginx vhosts that proxy to the ServerPilot dashboard process.
// They intentionally have no Docker container and must not appear as orphaned sites.
func isDashboardSite(site nginx.Site, configContent string, opts ComputeOptions) bool {
	if strings.Contains(configContent, nginx.DashboardSiteMarker) {
		return true
	}
	if opts.DashboardDomain != "" && strings.EqualFold(site.Domain, opts.DashboardDomain) {
		return true
	}
	if opts.DashboardPort < 1 || site.ProxyPass == "" {
		return false
	}
	port, err := extractPortFromProxyPass(site.ProxyPass)
	if err != nil || port != strconv.Itoa(opts.DashboardPort) {
		return false
	}
	if !strings.Contains(site.ProxyPass, "127.0.0.1") && !strings.Contains(site.ProxyPass, "localhost") {
		return false
	}
	meta := templates.ParseMetadataFromConfig(configContent)
	if meta.SiteID != "" || meta.ContainerID != "" || meta.Template != "" {
		return false
	}
	// Legacy dashboard vhosts created before DashboardSiteMarker (sp expose template).
	return strings.Contains(configContent, "proxy_buffering off") &&
		strings.Contains(configContent, "proxy_read_timeout 86400")
}

func readConfigSafe(name string) string {
	content, err := nginx.ReadConfigContent(name)
	if err != nil {
		return ""
	}
	return content
}

// MapContainersToSites returns mapped container/site pairs.
func MapContainersToSites() ([]Mapping, error) {
	r, err := ComputeAllMappings()
	if err != nil {
		return nil, err
	}
	return r.Mapped, nil
}

// matchesProxyPass checks if a proxy_pass URL targets the given host port exactly.
func matchesProxyPass(proxyPass, hostPort string) bool {
	if hostPort == "" || proxyPass == "" {
		return false
	}
	port, err := extractPortFromProxyPass(proxyPass)
	if err != nil {
		return false
	}
	return port == hostPort
}

// extractPortFromProxyPass extracts the port number from a proxy_pass URL.
func extractPortFromProxyPass(proxyPass string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(proxyPass))
	if err == nil && u.Host != "" {
		_, port, err := netHostPort(u.Host)
		if err == nil && port != "" {
			return port, nil
		}
	}
	idx := strings.LastIndex(proxyPass, ":")
	if idx == -1 {
		return "", fmt.Errorf("port not found")
	}
	rest := proxyPass[idx+1:]
	if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
		rest = rest[:slashIdx]
	}
	rest = strings.TrimRight(strings.TrimSpace(rest), ";")
	for _, c := range rest {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("invalid port")
		}
	}
	if rest == "" {
		return "", fmt.Errorf("invalid port")
	}
	return rest, nil
}

func netHostPort(host string) (string, string, error) {
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end == -1 {
			return "", "", fmt.Errorf("invalid host")
		}
		h := host[1:end]
		if end+1 < len(host) && host[end+1] == ':' {
			return h, host[end+2:], nil
		}
		return h, "", nil
	}
	h, p, ok := strings.Cut(host, ":")
	if !ok {
		return host, "", nil
	}
	return h, p, nil
}
