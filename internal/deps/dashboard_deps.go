package deps

import "os"

// DashboardDependency describes one optional or required host component for the
// ServerPilot dashboard. Install slugs map to knownDependencies in the web
// handler — never accept arbitrary slugs from clients.
type DashboardDependency struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Required    bool   `json:"required"`
	Installable bool   `json:"installable"`
	Reason      string `json:"reason,omitempty"`
}

// DockerInstalled reports whether the docker CLI is on the host.
func DockerInstalled() bool {
	return isInstalled(dockerPaths)
}

// NginxInstalled reports whether nginx is on the host.
func NginxInstalled() bool {
	return isInstalled(nginxPaths)
}

// ACLToolsInstalled reports whether setfacl is available.
func ACLToolsInstalled() bool {
	if _, err := os.Stat("/usr/bin/setfacl"); err == nil {
		return true
	}
	if _, err := os.Stat("/usr/sbin/setfacl"); err == nil {
		return true
	}
	return false
}

// FixDockerAptSources corrects mismatched Docker apt source entries.
func FixDockerAptSources() {
	fixDockerAptSources()
}

// ListDashboardDependencies returns install state for dashboard-managed packages.
func ListDashboardDependencies() []DashboardDependency {
	out := []DashboardDependency{
		{
			ID:          "docker",
			Name:        "Docker",
			Description: "Container runtime required for deployments and the dashboard",
			Installed:   DockerInstalled(),
			Required:    true,
			Installable: aptInstallSupported(),
			Reason:      "Core dependency — run sp setup or install from the dashboard",
		},
		{
			ID:          "nginx",
			Name:        "Nginx",
			Description: "Reverse proxy for public sites and the ServerPilot panel",
			Installed:   NginxInstalled(),
			Required:    true,
			Installable: aptInstallSupported(),
			Reason:      "Core dependency — run sp setup or install from the dashboard",
		},
	}

	if DockerInstalled() {
		pkg := ComposePluginPackageForDistro()
		out = append(out, DashboardDependency{
			ID:          ComposePluginPackage,
			Name:        "Docker Compose",
			Description: "Compose v2 plugin (docker compose) for Camino 2 stacks and sp compose deploy",
			Installed:   ComposeAvailable(),
			Required:    false,
			Installable: pkg != "",
			Reason:      "Required for multi-service compose bootstrap",
		})
	}

	out = append(out,
		DashboardDependency{
			ID:          "certbot",
			Name:        "Certbot",
			Description: "Let's Encrypt certificates for HTTPS sites",
			Installed:   IsCertbotInstalled(),
			Required:    false,
			Installable: aptInstallSupported(),
			Reason:      "Needed when enabling SSL from the dashboard",
		},
		DashboardDependency{
			ID:          "acl",
			Name:        "POSIX ACL tools",
			Description: "setfacl/getfacl for per-user folder permissions on /opt apps",
			Installed:   ACLToolsInstalled(),
			Required:    false,
			Installable: aptInstallSupported(),
			Reason:      "Needed for managed-app filesystem permissions",
		},
	)
	return out
}

func aptInstallSupported() bool {
	switch distroID() {
	case "debian", "ubuntu":
		return true
	default:
		return false
	}
}
