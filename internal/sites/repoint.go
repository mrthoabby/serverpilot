package sites

import (
	"fmt"
	"time"

	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

type repointPlan struct {
	record   SiteRecord
	oldPort  int
	newPort  int
	original string
	rendered string
}

// RepointHostPort re-renders a managed site's nginx config to a new host port,
// validates, reloads nginx, and updates the registry.
func RepointHostPort(siteID string, newHostPort int) error {
	if newHostPort < 1 || newHostPort > 65535 {
		return fmt.Errorf("invalid host port")
	}
	rec, ok, err := GetByID(siteID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("site not found")
	}
	if rec.HostPort == newHostPort {
		return nil
	}
	if rec.State == StateRedirectOverlay {
		return fmt.Errorf("cannot repoint site while redirect overlay is active")
	}

	meta := templates.SiteMetadata{
		SiteID:        rec.ID,
		ContainerID:   rec.ContainerID,
		ContainerName: rec.ContainerName,
		HostPort:      newHostPort,
		ContainerPort: rec.ContainerPort,
		Template:      string(rec.Template),
	}
	config, err := templates.RenderProxyConfig(templates.RenderSpec{
		Domain:     rec.Domain,
		Port:       newHostPort,
		Template:   rec.Template,
		Options:    rec.Options,
		Metadata:   meta,
		IncludeWWW: hasWWWAlias(rec.Domain),
	})
	if err != nil {
		return err
	}
	if _, err := nginx.WriteConfigContent(rec.ConfigName, config, true); err != nil {
		return fmt.Errorf("failed to update nginx config")
	}
	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("failed to reload nginx")
	}
	rec.HostPort = newHostPort
	rec.UpdatedAt = time.Now().UTC()
	return Upsert(rec)
}

// RepointSitesHostPort repoints every site in siteIDs to newHostPort.
func RepointSitesHostPort(siteIDs []string, newHostPort int) error {
	ports := make(map[string]int, len(siteIDs))
	for _, id := range siteIDs {
		ports[id] = newHostPort
	}
	return RepointSitesHostPorts(ports)
}

// RepointSitesHostPorts validates and installs all requested site changes,
// reloads nginx once, and restores every config if any step fails.
func RepointSitesHostPorts(ports map[string]int) error {
	plans := make([]repointPlan, 0, len(ports))
	for id, newPort := range ports {
		if newPort < 1 || newPort > 65535 {
			return fmt.Errorf("invalid host port")
		}
		rec, ok, err := GetByID(id)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("site not found")
		}
		if rec.State == StateRedirectOverlay {
			return fmt.Errorf("cannot repoint site while redirect overlay is active")
		}
		if rec.HostPort == newPort {
			continue
		}
		original, err := nginx.ReadConfigContent(rec.ConfigName)
		if err != nil {
			return err
		}
		rendered, err := renderSiteAtPort(rec, newPort)
		if err != nil {
			return err
		}
		plans = append(plans, repointPlan{
			record:   rec,
			oldPort:  rec.HostPort,
			newPort:  newPort,
			original: original,
			rendered: rendered,
		})
	}
	if len(plans) == 0 {
		return nil
	}

	restore := func() {
		for _, plan := range plans {
			_, _ = nginx.WriteConfigContent(plan.record.ConfigName, plan.original, false)
		}
		_ = nginx.ReloadNginx()
	}
	for _, plan := range plans {
		if _, err := nginx.WriteConfigContent(plan.record.ConfigName, plan.rendered, true); err != nil {
			restore()
			return fmt.Errorf("failed to update nginx config")
		}
	}
	if err := nginx.ReloadNginx(); err != nil {
		restore()
		return fmt.Errorf("failed to reload nginx")
	}
	if err := updateSiteHostPorts(ports); err != nil {
		restore()
		return err
	}
	return nil
}

func renderSiteAtPort(rec SiteRecord, newHostPort int) (string, error) {
	meta := templates.SiteMetadata{
		SiteID:        rec.ID,
		ContainerID:   rec.ContainerID,
		ContainerName: rec.ContainerName,
		HostPort:      newHostPort,
		ContainerPort: rec.ContainerPort,
		Template:      string(rec.Template),
	}
	return templates.RenderProxyConfig(templates.RenderSpec{
		Domain:     rec.Domain,
		Port:       newHostPort,
		Template:   rec.Template,
		Options:    rec.Options,
		Metadata:   meta,
		IncludeWWW: hasWWWAlias(rec.Domain),
	})
}

func hasWWWAlias(domain string) bool {
	// Best-effort: check if www config exists as sibling site record.
	all, err := List()
	if err != nil {
		return false
	}
	www := "www." + domain
	for _, s := range all {
		if s.Domain == www {
			return true
		}
	}
	return false
}

func updateSiteHostPorts(ports map[string]int) error {
	now := time.Now().UTC()
	for id, newPort := range ports {
		rec, ok, err := GetByID(id)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("site not found")
		}
		if rec.HostPort == newPort {
			continue
		}
		rec.HostPort = newPort
		rec.UpdatedAt = now
		if err := Upsert(rec); err != nil {
			return err
		}
	}
	return nil
}
