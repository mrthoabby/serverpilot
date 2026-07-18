package sites

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

// CreateRequest is the input for creating a managed container-bound site.
type CreateRequest struct {
	ContainerID         string
	ContainerName       string
	HostPort            int
	ContainerPort       int
	Domain              string
	Template            templates.TemplateType
	Options             templates.TemplateOptions
	IncludeWWW          bool
	AllowSharedHostPort bool
	ReplaceExisting     bool
}

// Create renders nginx config, enables the site, and records ownership.
func Create(req CreateRequest) (SiteRecord, error) {
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Domain == "" {
		return SiteRecord{}, fmt.Errorf("domain required")
	}
	if req.HostPort < 1 || req.HostPort > 65535 {
		return SiteRecord{}, fmt.Errorf("invalid host port")
	}
	if !templates.ValidTemplateType(req.Template) {
		return SiteRecord{}, fmt.Errorf("invalid template type")
	}

	existing, err := SitesOnHostPort(req.HostPort)
	if err != nil {
		return SiteRecord{}, err
	}
	if len(existing) > 0 && !req.AllowSharedHostPort {
		return SiteRecord{}, fmt.Errorf("host port already has a managed site")
	}

	if req.ReplaceExisting {
		if err := nginx.RemoveSiteFiles(req.Domain); err != nil {
			return SiteRecord{}, fmt.Errorf("failed to remove existing site")
		}
		_ = deleteByDomain(req.Domain)
	}

	siteID, err := NewSiteID()
	if err != nil {
		return SiteRecord{}, fmt.Errorf("failed to allocate site id")
	}

	meta := templates.SiteMetadata{
		SiteID:        siteID,
		ContainerID:   req.ContainerID,
		ContainerName: req.ContainerName,
		HostPort:      req.HostPort,
		ContainerPort: req.ContainerPort,
		Template:      string(req.Template),
	}
	opts, err := templates.MergeOptions(req.Template, req.Options)
	if err != nil {
		return SiteRecord{}, err
	}

	config, err := templates.RenderProxyConfig(templates.RenderSpec{
		Domain:     req.Domain,
		Port:       req.HostPort,
		Template:   req.Template,
		Options:    opts,
		Metadata:   meta,
		IncludeWWW: req.IncludeWWW,
	})
	if err != nil {
		return SiteRecord{}, err
	}

	configPath := filepath.Join("/etc/nginx/sites-available", req.Domain)
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return SiteRecord{}, fmt.Errorf("invalid config path")
	}
	if !strings.HasPrefix(absPath, "/etc/nginx/") {
		return SiteRecord{}, fmt.Errorf("config path is outside nginx directory")
	}

	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return SiteRecord{}, fmt.Errorf("site already exists")
		}
		return SiteRecord{}, fmt.Errorf("failed to write config")
	}
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		_ = os.Remove(absPath)
		return SiteRecord{}, fmt.Errorf("failed to write config")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(absPath)
		return SiteRecord{}, fmt.Errorf("failed to close config")
	}

	if err := nginx.EnableSite(req.Domain); err != nil {
		_ = os.Remove(absPath)
		return SiteRecord{}, fmt.Errorf("failed to enable site")
	}
	if err := nginx.ReloadNginx(); err != nil {
		return SiteRecord{}, fmt.Errorf("failed to reload nginx")
	}

	rec := SiteRecord{
		ID:            siteID,
		ContainerID:   req.ContainerID,
		ContainerName: req.ContainerName,
		HostPort:      req.HostPort,
		ContainerPort: req.ContainerPort,
		Domain:        req.Domain,
		ConfigName:    req.Domain,
		Template:      req.Template,
		Options:       opts,
		State:         StateActive,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := Upsert(rec); err != nil {
		return rec, fmt.Errorf("site created but registry update failed")
	}
	return rec, nil
}

func deleteByDomain(domain string) error {
	all, err := List()
	if err != nil {
		return err
	}
	for _, s := range all {
		if strings.EqualFold(s.Domain, domain) || s.ConfigName == domain {
			return Delete(s.ID)
		}
	}
	return nil
}

// AdoptFromConfig creates or updates a registry record from nginx metadata in an existing config.
func AdoptFromConfig(configName, content string, fallbackHostPort int) (SiteRecord, bool) {
	meta := templates.ParseMetadataFromConfig(content)
	if meta.SiteID == "" {
		return SiteRecord{}, false
	}
	rec := SiteRecord{
		ID:            meta.SiteID,
		ContainerID:   meta.ContainerID,
		ContainerName: meta.ContainerName,
		HostPort:      meta.HostPort,
		ContainerPort: meta.ContainerPort,
		Domain:        configName,
		ConfigName:    configName,
		Template:      templates.TemplateType(meta.Template),
		State:         StateActive,
	}
	if rec.HostPort == 0 {
		rec.HostPort = fallbackHostPort
	}
	if rec.Template == "" {
		rec.Template = templates.API
	}
	_ = Upsert(rec)
	return rec, true
}

// SwitchHostPort updates a managed site's host port in the registry.
func SwitchHostPort(siteID string, newHostPort int) error {
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
	rec.HostPort = newHostPort
	rec.UpdatedAt = time.Now().UTC()
	return Upsert(rec)
}
