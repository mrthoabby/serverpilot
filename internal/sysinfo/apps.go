package sysinfo

// apps.go — installed application detection and secure uninstall.
//
// SECURITY: All exec.Command arguments are 100% hardcoded in the static
// `registry` map below. User input (app_id) is ONLY used as a map-lookup key
// and never reaches any exec.Command call (CWE-78 mitigation).
// os.RemoveAll paths are also hardcoded in the registry (CWE-22 mitigation).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// InstalledApp is the JSON-serialisable view returned to the frontend.
type InstalledApp struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Version     string  `json:"version"`
	Manager     string  `json:"manager"` // "apt", "snap", "npm", "manual"
	SizeMB      float64 `json:"size_mb"`
	Running     bool    `json:"running"`
	Removable   bool    `json:"removable"`
}

// UninstallResult is returned by UninstallApp.
type UninstallResult struct {
	AppID        string   `json:"app_id"`
	AppName      string   `json:"app_name"`
	StepsDone    int      `json:"steps_done"`
	RemovedPaths []string `json:"removed_paths"`
	Warnings     []string `json:"warnings"`
}

// appDef is fully internal — never exposed to or constructed from user input.
// Every []string that reaches exec.Command is a literal in this file.
type appDef struct {
	ID          string
	Name        string
	Description string
	Manager     string
	// Detection — checked with os.Stat; first existing path is used.
	BinaryPaths []string
	// Version command: absolute binary path + hardcoded args.
	VersionCmd []string
	// dpkg package name for size estimation (empty = skip).
	PackageName string
	// serviceNames checked with "systemctl is-active" to detect if running.
	ServiceNames []string
	// processNames checked with "pgrep -x" when no service name matches.
	ProcessNames []string
	// PreStop: commands run before uninstall (e.g. systemctl stop).
	// All arguments are literal strings — no user input.
	PreStop [][]string
	// Uninstall: main removal commands.
	Uninstall [][]string
	// CleanPaths: additional filesystem paths removed with os.RemoveAll.
	// All paths are hardcoded literals — no path traversal possible.
	CleanPaths []string
}

// registry is the single source of truth for every supported application.
// It is a package-level constant (never modified at runtime).
// User input (app_id) only selects a KEY — values are never touched by callers.
var registry = map[string]appDef{

	"docker": {
		ID:           "docker",
		Name:         "Docker",
		Description:  "Container platform and runtime",
		Manager:      "apt",
		BinaryPaths:  []string{"/usr/bin/docker"},
		VersionCmd:   []string{"/usr/bin/docker", "--version"},
		PackageName:  "docker-ce",
		ServiceNames: []string{"docker"},
		PreStop: [][]string{
			{"/usr/bin/systemctl", "stop", "docker"},
			{"/usr/bin/systemctl", "disable", "docker"},
		},
		Uninstall: [][]string{
			{"/usr/bin/apt-get", "purge", "-y",
				"docker-ce", "docker-ce-cli", "containerd.io",
				"docker-buildx-plugin", "docker-compose-plugin", "docker-compose"},
			{"/usr/bin/apt-get", "autoremove", "-y"},
		},
		CleanPaths: []string{
			"/var/lib/docker",
			"/etc/docker",
		},
	},

	"nodejs": {
		ID:           "nodejs",
		Name:         "Node.js",
		Description:  "JavaScript runtime environment",
		Manager:      "apt",
		BinaryPaths:  []string{"/usr/bin/node", "/usr/local/bin/node"},
		VersionCmd:   []string{"/usr/bin/node", "--version"},
		PackageName:  "nodejs",
		ProcessNames: []string{"node"},
		Uninstall: [][]string{
			{"/usr/bin/apt-get", "purge", "-y", "nodejs", "npm"},
			{"/usr/bin/apt-get", "autoremove", "-y"},
		},
		CleanPaths: []string{
			"/usr/local/lib/node_modules",
			"/usr/lib/node_modules",
			"/root/.npm",
			"/root/.node_repl_history",
		},
	},

	"nginx": {
		ID:           "nginx",
		Name:         "nginx",
		Description:  "Web server and reverse proxy",
		Manager:      "apt",
		BinaryPaths:  []string{"/usr/sbin/nginx"},
		VersionCmd:   []string{"/usr/sbin/nginx", "-v"},
		PackageName:  "nginx",
		ServiceNames: []string{"nginx"},
		PreStop: [][]string{
			{"/usr/bin/systemctl", "stop", "nginx"},
			{"/usr/bin/systemctl", "disable", "nginx"},
		},
		Uninstall: [][]string{
			{"/usr/bin/apt-get", "purge", "-y", "nginx", "nginx-common", "nginx-core", "nginx-full"},
			{"/usr/bin/apt-get", "autoremove", "-y"},
		},
		CleanPaths: []string{
			"/etc/nginx",
			"/var/log/nginx",
		},
	},

	"certbot": {
		ID:          "certbot",
		Name:        "Certbot",
		Description: "Let's Encrypt SSL certificate manager",
		Manager:     "apt",
		BinaryPaths: []string{"/usr/bin/certbot"},
		VersionCmd:  []string{"/usr/bin/certbot", "--version"},
		PackageName: "certbot",
		Uninstall: [][]string{
			{"/usr/bin/apt-get", "purge", "-y", "certbot", "python3-certbot-nginx"},
			{"/usr/bin/apt-get", "autoremove", "-y"},
		},
		CleanPaths: []string{
			"/etc/letsencrypt",
			"/var/log/letsencrypt",
		},
	},

	"pm2": {
		ID:           "pm2",
		Name:         "PM2",
		Description:  "Node.js process manager",
		Manager:      "npm",
		BinaryPaths:  []string{"/usr/local/bin/pm2", "/usr/bin/pm2"},
		VersionCmd:   []string{"/usr/local/bin/pm2", "--version"},
		ServiceNames: []string{"pm2-root"},
		ProcessNames: []string{"pm2"},
		PreStop: [][]string{
			{"/usr/local/bin/pm2", "kill"},
		},
		Uninstall: [][]string{
			{"/usr/local/bin/npm", "uninstall", "-g", "pm2"},
		},
		CleanPaths: []string{
			"/root/.pm2",
		},
	},

	"golang": {
		ID:          "golang",
		Name:        "Go",
		Description: "Go programming language runtime (official install)",
		Manager:     "manual",
		BinaryPaths: []string{"/usr/local/go/bin/go"},
		VersionCmd:  []string{"/usr/local/go/bin/go", "version"},
		// No apt package for official Go — it is installed as a directory.
		// CleanPaths handles the full removal.
		CleanPaths: []string{
			"/usr/local/go",
		},
	},

	"python3": {
		ID:          "python3",
		Name:        "Python 3",
		Description: "Python 3 interpreter",
		Manager:     "apt",
		BinaryPaths: []string{"/usr/bin/python3"},
		VersionCmd:  []string{"/usr/bin/python3", "--version"},
		PackageName: "python3",
		Uninstall: [][]string{
			{"/usr/bin/apt-get", "purge", "-y", "python3", "python3-pip"},
			{"/usr/bin/apt-get", "autoremove", "-y"},
		},
		CleanPaths: []string{},
	},
}

// DetectApps scans the host for apps defined in the registry and returns
// only those whose binary path exists on disk.
func DetectApps() []InstalledApp {
	var apps []InstalledApp
	for _, def := range registry {
		if a := detectApp(def); a != nil {
			apps = append(apps, *a)
		}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	return apps
}

// detectApp returns nil when the application is not installed.
func detectApp(def appDef) *InstalledApp {
	// Confirm at least one binary exists.
	var foundBinary string
	for _, p := range def.BinaryPaths {
		if _, err := os.Stat(p); err == nil {
			foundBinary = p
			break
		}
	}
	if foundBinary == "" {
		return nil
	}

	app := &InstalledApp{
		ID:          def.ID,
		Name:        def.Name,
		Description: def.Description,
		Manager:     def.Manager,
		Removable:   true,
	}

	// Version — use CombinedOutput because some tools (nginx -v) write to stderr.
	if len(def.VersionCmd) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, def.VersionCmd[0], def.VersionCmd[1:]...)
		if out, err := cmd.CombinedOutput(); err == nil {
			app.Version = cleanVersionString(string(out))
		}
	}

	// Running state — systemctl first, then pgrep.
	app.Running = isAppRunning(def)

	// Package size from dpkg.
	if def.PackageName != "" {
		app.SizeMB = dpkgInstalledSizeMB(def.PackageName)
	}

	return app
}

// cleanVersionString extracts a tidy version string from raw command output.
func cleanVersionString(raw string) string {
	line := strings.SplitN(strings.TrimSpace(raw), "\n", 2)[0]
	// Strip common prefixes so the UI shows just the version number/tag.
	for _, prefix := range []string{
		"Docker version ", "node ", "nginx version: nginx/",
		"certbot ", "pm2 ", "go ", "Python ", "git version ",
	} {
		if strings.HasPrefix(line, prefix) {
			line = strings.TrimPrefix(line, prefix)
			// Further trim trailing comma/space (Docker: "24.0.7, build ...")
			if idx := strings.Index(line, ","); idx != -1 {
				line = line[:idx]
			}
			break
		}
	}
	if len(line) > 80 {
		line = line[:80]
	}
	return strings.TrimSpace(line)
}

// isAppRunning checks whether the application has a running process.
func isAppRunning(def appDef) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, svc := range def.ServiceNames {
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", svc)
		if cmd.Run() == nil {
			return true
		}
	}
	for _, proc := range def.ProcessNames {
		cmd := exec.CommandContext(ctx, "/usr/bin/pgrep", "-x", proc)
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}

// dpkgInstalledSizeMB returns the installed size in MB from dpkg-query.
// Returns 0 when the package is unknown or the query fails.
func dpkgInstalledSizeMB(pkg string) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// dpkg-query returns Installed-Size in kibibytes.
	cmd := exec.CommandContext(ctx,
		"/usr/bin/dpkg-query", "-W", "--showformat=${Installed-Size}", pkg)
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	var kb float64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%f", &kb)
	return kb / 1024
}

// UninstallApp runs the hardcoded uninstall sequence for the given app ID.
//
// SECURITY: appID is validated against the static registry before anything
// executes. Every exec.Command receives a hardcoded []string — the appID
// string never appears in any argument position (CWE-78).
// os.RemoveAll paths are hardcoded registry literals (CWE-22).
func UninstallApp(appID string) (*UninstallResult, error) {
	// Allowlist check — appID only selects a registry entry; it is never
	// interpolated into any command or filesystem path.
	def, ok := registry[appID]
	if !ok {
		return nil, fmt.Errorf("unknown application: not in approved list")
	}

	result := &UninstallResult{
		AppID:   def.ID,
		AppName: def.Name,
	}

	// 10-minute total timeout — apt purges can be slow on first run.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	runStep := func(args []string) {
		// All args are hardcoded literals from the registry.
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			result.Warnings = append(result.Warnings,
				strings.TrimSpace(string(out)))
		}
		result.StepsDone++
	}

	for _, step := range def.PreStop {
		runStep(step)
	}
	for _, step := range def.Uninstall {
		runStep(step)
	}

	// Remove hardcoded extra paths.
	for _, p := range def.CleanPaths {
		if err := os.RemoveAll(p); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("remove %s: %v", p, err))
		} else {
			result.RemovedPaths = append(result.RemovedPaths, p)
		}
		result.StepsDone++
	}

	return result, nil
}
