package sites

import (
	"strconv"
	"strings"
)

// RegistryHostPortForContainer returns the host port recorded for the first
// site linked to containerName. This is the canonical nginx target for Camino A
// deploys (plain docker run + sp sites).
func RegistryHostPortForContainer(containerName string) (int, bool, error) {
	containerName = strings.TrimSpace(containerName)
	if containerName == "" {
		return 0, false, nil
	}
	recs, err := SitesForContainer("", containerName)
	if err != nil {
		return 0, false, err
	}
	for _, rec := range recs {
		if rec.HostPort > 0 {
			return rec.HostPort, true, nil
		}
	}
	return 0, false, nil
}

// FormatHostPort returns the decimal host port string for shell scripts.
func FormatHostPort(port int) string {
	return strconv.Itoa(port)
}
