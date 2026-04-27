package web

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/sysinfo"
)

//go:embed static
var staticFiles embed.FS

// Server holds the web server configuration and dependencies.
type Server struct {
	config       *auth.Config
	port         int
	version      string
	sessionStore *auth.SessionStore
}

// NewServer creates a new web server instance.
func NewServer(config *auth.Config, port int, version string) *Server {
	return &Server{
		config:       config,
		port:         port,
		version:      version,
		sessionStore: auth.NewSessionStore(),
	}
}

// Start starts the HTTP server and blocks until it returns.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Dashboard route.
	mux.HandleFunc("/", s.handleDashboard)

	// Auth API routes (no auth middleware).
	mux.HandleFunc("/api/login", s.handleLogin)

	// Protected API routes.
	mux.Handle("/api/logout", s.authMiddleware(http.HandlerFunc(s.handleLogout)))
	mux.Handle("/api/containers", s.authMiddleware(http.HandlerFunc(s.handleContainers)))
	mux.Handle("/api/images", s.authMiddleware(http.HandlerFunc(s.handleImages)))
	mux.Handle("/api/images/delete", s.authMiddleware(http.HandlerFunc(s.handleImagesDelete)))
	mux.Handle("/api/sites", s.authMiddleware(http.HandlerFunc(s.handleSites)))
	mux.Handle("/api/mappings", s.authMiddleware(http.HandlerFunc(s.handleMappings)))
	mux.Handle("/api/ssl/enable", s.authMiddleware(http.HandlerFunc(s.handleSSLEnable)))
	mux.Handle("/api/ssl/disable", s.authMiddleware(http.HandlerFunc(s.handleSSLDisable)))
	mux.Handle("/api/sites/create", s.authMiddleware(http.HandlerFunc(s.handleSiteCreate)))
	mux.Handle("/api/sites/enable", s.authMiddleware(http.HandlerFunc(s.handleSiteEnable)))
	mux.Handle("/api/sites/disable", s.authMiddleware(http.HandlerFunc(s.handleSiteDisable)))
	mux.Handle("/api/sites/config", s.authMiddleware(http.HandlerFunc(s.handleSiteConfigRead)))
	mux.Handle("/api/sites/config/save", s.authMiddleware(http.HandlerFunc(s.handleSiteConfigSave)))
	mux.Handle("/api/sites/delete", s.authMiddleware(http.HandlerFunc(s.handleSiteDelete)))
	mux.Handle("/api/system", s.authMiddleware(http.HandlerFunc(s.handleSystem)))
	mux.Handle("/api/system/memory-detail", s.authMiddleware(http.HandlerFunc(s.handleMemoryDetail)))
	mux.Handle("/api/system/disk-breakdown", s.authMiddleware(http.HandlerFunc(s.handleDiskBreakdown)))
	mux.Handle("/api/system/disk-detail", s.authMiddleware(http.HandlerFunc(s.handleDiskDetail)))
	mux.Handle("/api/system/disk-top-files", s.authMiddleware(http.HandlerFunc(s.handleDiskTopFiles)))
	mux.Handle("/api/system/disk-clean", s.authMiddleware(http.HandlerFunc(s.handleDiskClean)))
	mux.Handle("/api/system/kill-process", s.authMiddleware(http.HandlerFunc(s.handleKillProcess)))
	mux.Handle("/api/system/port", s.authMiddleware(http.HandlerFunc(s.handlePortAllocate)))
	mux.Handle("/api/system/disk-hidden-files", s.authMiddleware(http.HandlerFunc(s.handleDiskHiddenFiles)))
	mux.Handle("/api/system/disk-hidden-files/add", s.authMiddleware(http.HandlerFunc(s.handleDiskHiddenFilesAdd)))
	mux.Handle("/api/system/disk-hidden-files/remove", s.authMiddleware(http.HandlerFunc(s.handleDiskHiddenFilesRemove)))
	mux.Handle("/api/labels", s.authMiddleware(http.HandlerFunc(s.handleLabelsGet)))
	mux.Handle("/api/labels/set", s.authMiddleware(http.HandlerFunc(s.handleLabelSet)))
	mux.Handle("/api/labels/remove", s.authMiddleware(http.HandlerFunc(s.handleLabelRemove)))
	mux.Handle("/api/version-check", s.authMiddleware(http.HandlerFunc(s.handleVersionCheck)))
	mux.Handle("/api/update", s.authMiddleware(http.HandlerFunc(s.handleUpdate)))
	mux.Handle("/api/settings", s.authMiddleware(http.HandlerFunc(s.handleSettingsGet)))
	mux.Handle("/api/settings/domain", s.authMiddleware(http.HandlerFunc(s.handleSettingsDomain)))
	mux.Handle("/api/settings/email", s.authMiddleware(http.HandlerFunc(s.handleSettingsEmail)))
	mux.Handle("/api/settings/ssl-enable", s.authMiddleware(http.HandlerFunc(s.handleSettingsSSLEnable)))
	mux.Handle("/api/settings/block-insecure", s.authMiddleware(http.HandlerFunc(s.handleSettingsBlockInsecure)))
	mux.Handle("/api/dependencies/install", s.authMiddleware(http.HandlerFunc(s.handleDependencyInstall)))
	mux.Handle("/api/gdapp/activate", s.authMiddleware(http.HandlerFunc(s.handleGDAppActivate)))
	mux.Handle("/api/gdapp/deactivate", s.authMiddleware(http.HandlerFunc(s.handleGDAppDeactivate)))

	// Deploy users.
	mux.Handle("/api/users", s.authMiddleware(http.HandlerFunc(s.handleDeployUsers)))
	mux.Handle("/api/users/create", s.authMiddleware(http.HandlerFunc(s.handleDeployUserCreate)))
	mux.Handle("/api/users/reset-password", s.authMiddleware(http.HandlerFunc(s.handleDeployUserResetPassword)))
	mux.Handle("/api/users/delete", s.authMiddleware(http.HandlerFunc(s.handleDeployUserDelete)))
	mux.Handle("/api/users/ssh-keys", s.authMiddleware(http.HandlerFunc(s.handleDeployUserSSHKeys)))
	mux.Handle("/api/users/ssh-keys/add", s.authMiddleware(http.HandlerFunc(s.handleDeployUserAddSSHKey)))

	// Google Cloud Firewall (conditional — only works if gcloud is installed).
	mux.Handle("/api/gcloud/status", s.authMiddleware(http.HandlerFunc(s.handleGCloudStatus)))
	mux.Handle("/api/gcloud/firewall", s.authMiddleware(http.HandlerFunc(s.handleFirewallRules)))
	mux.Handle("/api/gcloud/firewall/open", s.authMiddleware(http.HandlerFunc(s.handleFirewallOpen)))
	mux.Handle("/api/gcloud/firewall/close", s.authMiddleware(http.HandlerFunc(s.handleFirewallClose)))

	// Installed applications.
	mux.Handle("/api/apps", s.authMiddleware(http.HandlerFunc(s.handleApps)))
	mux.Handle("/api/apps/uninstall", s.authMiddleware(http.HandlerFunc(s.handleAppUninstall)))

	// Managed applications (/opt directories with .env files).
	mux.Handle("/api/managed-apps", s.authMiddleware(http.HandlerFunc(s.handleManagedApps)))
	mux.Handle("/api/managed-apps/create", s.authMiddleware(http.HandlerFunc(s.handleManagedAppCreate)))
	mux.Handle("/api/managed-apps/delete", s.authMiddleware(http.HandlerFunc(s.handleManagedAppDelete)))
	mux.Handle("/api/managed-apps/env", s.authMiddleware(http.HandlerFunc(s.handleEnvFileRead)))
	mux.Handle("/api/managed-apps/env/create", s.authMiddleware(http.HandlerFunc(s.handleEnvFileCreate)))
	mux.Handle("/api/managed-apps/env/save", s.authMiddleware(http.HandlerFunc(s.handleEnvFileSave)))
	mux.Handle("/api/managed-apps/env/delete", s.authMiddleware(http.HandlerFunc(s.handleEnvFileDelete)))

	// Cases — operator notes/scenarios (public or private).
	mux.Handle("/api/cases", s.authMiddleware(http.HandlerFunc(s.handleCasesList)))
	mux.Handle("/api/cases/create", s.authMiddleware(http.HandlerFunc(s.handleCasesCreate)))
	mux.Handle("/api/cases/update", s.authMiddleware(http.HandlerFunc(s.handleCasesUpdate)))
	mux.Handle("/api/cases/delete", s.authMiddleware(http.HandlerFunc(s.handleCasesDelete)))

	// Static files.
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Initialise the scanner/bot detection logger (non-fatal if log path is unavailable).
	initScannerLogger()

	// Wrap everything with security, logging, and recovery middleware.
	// Order: Recovery (outermost) → Logging → Security → ClientHeader → BodyLimit → routes.
	// BodyLimit caps POST payloads at 1 MB to prevent memory exhaustion.
	handler := RecoveryMiddleware(LoggingMiddleware(s.SecurityMiddleware(s.ClientHeaderMiddleware(BodyLimitMiddleware(mux)))))

	// Start the background memory history collector (snapshots every 5 min).
	sysinfo.StartHistoryCollector()

	// When SSL is enabled, bind only to localhost so the Go server is NOT
	// directly reachable from the internet — all traffic must go through nginx
	// which handles SSL termination. This prevents bypassing HTTPS.
	var addr string
	if s.config.SSLEnabled && s.config.Domain != "" {
		addr = fmt.Sprintf("127.0.0.1:%d", s.port)
		log.Printf("SSL enabled — binding to %s (localhost only, behind nginx)", addr)
	} else {
		addr = fmt.Sprintf(":%d", s.port)
		log.Printf("Starting server on %s (all interfaces)", addr)
	}
	return http.ListenAndServe(addr, handler)
}
