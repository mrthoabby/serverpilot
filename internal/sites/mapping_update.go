package sites

import (
	"fmt"
	"strings"
)

// ResolveManagedSite finds a registry record by id, config filename, or domain.
func ResolveManagedSite(siteID, configName, domain string) (SiteRecord, error) {
	siteID = strings.TrimSpace(siteID)
	if siteID != "" {
		rec, ok, err := GetByID(siteID)
		if err != nil {
			return SiteRecord{}, err
		}
		if ok {
			return rec, nil
		}
	}

	configName = strings.TrimSpace(configName)
	if configName != "" {
		rec, ok, err := GetByConfigName(configName)
		if err != nil {
			return SiteRecord{}, err
		}
		if ok {
			return rec, nil
		}
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain != "" {
		all, err := List()
		if err != nil {
			return SiteRecord{}, err
		}
		for _, rec := range all {
			if strings.EqualFold(rec.Domain, domain) || rec.ConfigName == domain {
				return rec, nil
			}
		}
	}

	return SiteRecord{}, fmt.Errorf("site not found")
}
