package web

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
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
	mux.Handle("/api/session/reauth", s.authMiddleware(http.HandlerFunc(s.handleSessionReauth)))
	mux.Handle("/api/sessions", s.authMiddleware(http.HandlerFunc(s.handleSessionsList)))
	mux.Handle("/api/sessions/revoke", s.requireReauth(http.HandlerFunc(s.handleSessionRevoke)))
	mux.Handle("/api/sessions/revoke-others", s.requireReauth(http.HandlerFunc(s.handleSessionRevokeOthers)))
	mux.Handle("/api/security/mfa/setup", s.requireReauth(http.HandlerFunc(s.handleMFASetup)))
	mux.Handle("/api/security/mfa/enable", s.requireReauth(http.HandlerFunc(s.handleMFAEnable)))
	mux.Handle("/api/security/mfa/disable", s.requireReauth(http.HandlerFunc(s.handleMFADisable)))
	mux.Handle("/api/containers", s.authMiddleware(http.HandlerFunc(s.handleContainers)))
	mux.Handle("/api/containers/logs", s.authMiddleware(http.HandlerFunc(s.handleContainerLogs)))
	mux.Handle("/api/containers/logs/clear", s.requireReauth(http.HandlerFunc(s.handleContainerLogsClear)))
	mux.Handle("/api/containers/reload-env", s.requireReauth(http.HandlerFunc(s.handleContainerReloadEnv)))
	mux.Handle("/api/container-replicas", s.authMiddleware(http.HandlerFunc(s.handleContainerReplicasList)))
	mux.Handle("/api/container-replicas/preview", s.authMiddleware(http.HandlerFunc(s.handleContainerReplicaPreview)))
	mux.Handle("/api/container-replicas/create", s.requireSecureReauth(http.HandlerFunc(s.handleContainerReplicaCreate)))
	mux.Handle("/api/container-replicas/sync", s.requireSecureReauth(http.HandlerFunc(s.handleContainerReplicaSync)))
	mux.Handle("/api/container-replicas/delete", s.requireSecureReauth(http.HandlerFunc(s.handleContainerReplicaDelete)))
	mux.Handle("/api/container-replicas/update", s.requireReauth(http.HandlerFunc(s.handleContainerReplicaUpdate)))
	mux.Handle("/api/images", s.authMiddleware(http.HandlerFunc(s.handleImages)))
	mux.Handle("/api/images/delete", s.requireSecureReauth(http.HandlerFunc(s.handleImagesDelete)))
	mux.Handle("/api/sites", s.authMiddleware(http.HandlerFunc(s.handleSites)))
	mux.Handle("/api/mappings", s.authMiddleware(http.HandlerFunc(s.handleMappings)))
	mux.Handle("/api/ssl/enable", s.requireReauth(http.HandlerFunc(s.handleSSLEnable)))
	mux.Handle("/api/ssl/disable", s.requireSecureReauth(http.HandlerFunc(s.handleSSLDisable)))
	mux.Handle("/api/sites/create", s.requireReauth(http.HandlerFunc(s.handleSiteCreate)))
	mux.Handle("/api/sites/enable", s.requireReauth(http.HandlerFunc(s.handleSiteEnable)))
	mux.Handle("/api/sites/disable", s.requireReauth(http.HandlerFunc(s.handleSiteDisable)))
	mux.Handle("/api/sites/enable-www", s.requireReauth(http.HandlerFunc(s.handleSiteEnableWWW)))
	mux.Handle("/api/sites/config", s.authMiddleware(http.HandlerFunc(s.handleSiteConfigRead)))
	mux.Handle("/api/sites/config/save", s.requireSecureReauth(http.HandlerFunc(s.handleSiteConfigSave)))
	mux.Handle("/api/sites/update-domain", s.requireSecureReauth(http.HandlerFunc(s.handleSiteUpdateDomain)))
	mux.Handle("/api/sites/delete", s.requireSecureReauth(http.HandlerFunc(s.handleSiteDelete)))
	mux.Handle("/api/system", s.authMiddleware(http.HandlerFunc(s.handleSystem)))
	mux.Handle("/api/system/memory-detail", s.authMiddleware(http.HandlerFunc(s.handleMemoryDetail)))
	mux.Handle("/api/system/disk-breakdown", s.authMiddleware(http.HandlerFunc(s.handleDiskBreakdown)))
	mux.Handle("/api/system/disk-detail", s.authMiddleware(http.HandlerFunc(s.handleDiskDetail)))
	mux.Handle("/api/system/disk-unaccounted", s.authMiddleware(http.HandlerFunc(s.handleDiskUnaccounted)))
	mux.Handle("/api/system/disk-top-files", s.authMiddleware(http.HandlerFunc(s.handleDiskTopFiles)))
	mux.Handle("/api/system/disk-clean", s.requireSecureReauth(http.HandlerFunc(s.handleDiskClean)))
	mux.Handle("/api/system/kill-process", s.requireSecureReauth(http.HandlerFunc(s.handleKillProcess)))
	mux.Handle("/api/system/port", s.authMiddleware(http.HandlerFunc(s.handlePortAllocate)))
	mux.Handle("/api/system/disk-hidden-files", s.authMiddleware(http.HandlerFunc(s.handleDiskHiddenFiles)))
	mux.Handle("/api/system/disk-hidden-files/add", s.requireReauth(http.HandlerFunc(s.handleDiskHiddenFilesAdd)))
	mux.Handle("/api/system/disk-hidden-files/remove", s.requireReauth(http.HandlerFunc(s.handleDiskHiddenFilesRemove)))
	mux.Handle("/api/labels", s.authMiddleware(http.HandlerFunc(s.handleLabelsGet)))
	mux.Handle("/api/labels/set", s.authMiddleware(http.HandlerFunc(s.handleLabelSet)))
	mux.Handle("/api/labels/remove", s.authMiddleware(http.HandlerFunc(s.handleLabelRemove)))
	mux.Handle("/api/version-check", s.authMiddleware(http.HandlerFunc(s.handleVersionCheck)))
	mux.Handle("/api/update", s.requireSecureReauth(http.HandlerFunc(s.handleUpdate)))
	mux.Handle("/api/settings", s.authMiddleware(http.HandlerFunc(s.handleSettingsGet)))
	mux.Handle("/api/settings/domain", s.requireReauth(http.HandlerFunc(s.handleSettingsDomain)))
	mux.Handle("/api/settings/email", s.requireReauth(http.HandlerFunc(s.handleSettingsEmail)))
	mux.Handle("/api/settings/ssl-enable", s.requireReauth(http.HandlerFunc(s.handleSettingsSSLEnable)))
	mux.Handle("/api/settings/block-insecure", s.requireSecureReauth(http.HandlerFunc(s.handleSettingsBlockInsecure)))
	mux.Handle("/api/settings/host-guard", s.requireSecureReauth(http.HandlerFunc(s.handleSettingsHostGuard)))
	mux.Handle("/api/dependencies/install", s.requireSecureReauth(http.HandlerFunc(s.handleDependencyInstall)))
	mux.Handle("/api/gdapp/activate", s.requireReauth(http.HandlerFunc(s.handleGDAppActivate)))
	mux.Handle("/api/gdapp/deactivate", s.requireSecureReauth(http.HandlerFunc(s.handleGDAppDeactivate)))

	// Deploy users.
	mux.Handle("/api/users", s.authMiddleware(http.HandlerFunc(s.handleDeployUsers)))
	mux.Handle("/api/users/create", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserCreate)))
	mux.Handle("/api/users/import", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserImport)))
	mux.Handle("/api/users/system", s.authMiddleware(http.HandlerFunc(s.handleSystemUsersList)))
	mux.Handle("/api/users/groups/toggle", s.requireSecureReauth(http.HandlerFunc(s.handleSystemUserGroupToggle)))

	// Database query module — saved connections (DSN encrypted in vault),
	// query runner with timeouts and result caps, audit log.
	mux.Handle("/api/db/connections", s.authMiddleware(http.HandlerFunc(s.handleDBConnectionsList)))
	mux.Handle("/api/db/connections/save", s.requireSecureReauth(http.HandlerFunc(s.handleDBConnectionsSave)))
	mux.Handle("/api/db/connections/delete", s.requireSecureReauth(http.HandlerFunc(s.handleDBConnectionsDelete)))
	mux.Handle("/api/db/connections/test", s.requireReauth(http.HandlerFunc(s.handleDBConnectionsTest)))
	mux.Handle("/api/db/query", s.requireReauth(http.HandlerFunc(s.handleDBQuery)))
	mux.Handle("/api/db/cell-update", s.requireSecureReauth(http.HandlerFunc(s.handleDBCellUpdate)))
	mux.Handle("/api/db/schema", s.authMiddleware(http.HandlerFunc(s.handleDBSchema)))
	mux.Handle("/api/db/audit", s.authMiddleware(http.HandlerFunc(s.handleDBAudit)))
	mux.Handle("/api/users/reset-password", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserResetPassword)))
	mux.Handle("/api/users/delete", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserDelete)))
	mux.Handle("/api/users/ssh-keys", s.authMiddleware(http.HandlerFunc(s.handleDeployUserSSHKeys)))
	mux.Handle("/api/users/ssh-keys/add", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserAddSSHKey)))
	// Server-side SSH keypair generation + encrypted vault for re-display.
	mux.Handle("/api/users/ssh-keys/generate", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserGenerateKey)))
	mux.Handle("/api/users/ssh-keys/private", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserPrivateKey)))
	mux.Handle("/api/users/ssh-keys/private/delete", s.requireSecureReauth(http.HandlerFunc(s.handleDeployUserPrivateKeyDelete)))
	mux.Handle("/api/users/ssh-keys/vault-status", s.authMiddleware(http.HandlerFunc(s.handleDeployUserKeyVaultStatus)))

	// Google Cloud Firewall (conditional — only works if gcloud is installed).
	mux.Handle("/api/gcloud/status", s.authMiddleware(http.HandlerFunc(s.handleGCloudStatus)))
	mux.Handle("/api/gcloud/firewall", s.authMiddleware(http.HandlerFunc(s.handleFirewallRules)))
	mux.Handle("/api/gcloud/firewall/open", s.requireSecureReauth(http.HandlerFunc(s.handleFirewallOpen)))
	mux.Handle("/api/gcloud/firewall/close", s.requireSecureReauth(http.HandlerFunc(s.handleFirewallClose)))

	// Installed applications.
	mux.Handle("/api/apps", s.authMiddleware(http.HandlerFunc(s.handleApps)))
	mux.Handle("/api/apps/uninstall", s.requireSecureReauth(http.HandlerFunc(s.handleAppUninstall)))

	// Managed applications (/opt directories with .env files).
	mux.Handle("/api/managed-apps", s.authMiddleware(http.HandlerFunc(s.handleManagedApps)))
	mux.Handle("/api/managed-apps/create", s.requireSecureReauth(http.HandlerFunc(s.handleManagedAppCreate)))
	mux.Handle("/api/managed-apps/delete", s.requireSecureReauth(http.HandlerFunc(s.handleManagedAppDelete)))
	mux.Handle("/api/managed-apps/env", s.authMiddleware(http.HandlerFunc(s.handleEnvFileRead)))
	mux.Handle("/api/managed-apps/env/create", s.requireSecureReauth(http.HandlerFunc(s.handleEnvFileCreate)))
	mux.Handle("/api/managed-apps/env/save", s.requireSecureReauth(http.HandlerFunc(s.handleEnvFileSave)))
	mux.Handle("/api/managed-apps/env/delete", s.requireSecureReauth(http.HandlerFunc(s.handleEnvFileDelete)))

	// Cases — operator notes/scenarios (public or private).
	mux.Handle("/api/cases", s.authMiddleware(http.HandlerFunc(s.handleCasesList)))
	mux.Handle("/api/cases/create", s.authMiddleware(http.HandlerFunc(s.handleCasesCreate)))
	mux.Handle("/api/cases/update", s.authMiddleware(http.HandlerFunc(s.handleCasesUpdate)))
	mux.Handle("/api/cases/delete", s.authMiddleware(http.HandlerFunc(s.handleCasesDelete)))

	// Permissions — per-user grants on managed app folders + system apps.
	// Every endpoint is behind authMiddleware AND CSRFMiddleware. Dangerous
	// grants additionally require a single-use confirm token (see handler).
	mux.Handle("/api/permissions/capabilities", s.authMiddleware(http.HandlerFunc(s.handlePermissionsCapabilities)))
	mux.Handle("/api/permissions/managed-app", s.authMiddleware(http.HandlerFunc(s.handlePermissionsManagedApp)))
	mux.Handle("/api/permissions/system-apps", s.authMiddleware(http.HandlerFunc(s.handlePermissionsSystemApps)))
	mux.Handle("/api/permissions/system-app", s.authMiddleware(http.HandlerFunc(s.handlePermissionsSystemApp)))
	mux.Handle("/api/permissions/confirm", s.requireSecureReauth(http.HandlerFunc(s.handlePermissionsConfirm)))
	mux.Handle("/api/permissions/fs/grant", s.requireSecureReauth(http.HandlerFunc(s.handlePermissionsFSGrant)))
	mux.Handle("/api/permissions/system/grant", s.requireSecureReauth(http.HandlerFunc(s.handlePermissionsSystemGrant)))
	mux.Handle("/api/permissions/audit", s.authMiddleware(http.HandlerFunc(s.handlePermissionsAudit)))

	// Static files.
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Initialise the scanner/bot detection logger (non-fatal if log path is unavailable).
	initScannerLogger()

	// Wrap everything with security, logging, and recovery middleware.
	// Order: Recovery (outermost) → Logging → Security → CSRF → ClientHeader → BodyLimit → routes.
	// CSRFMiddleware enforces an Origin/Referer check on state-changing requests
	// (CWE-352); BodyLimit caps POST payloads at 1 MB to prevent memory exhaustion.
	handler := RecoveryMiddleware(LoggingMiddleware(s.SecurityMiddleware(s.CSRFMiddleware(s.ClientHeaderMiddleware(BodyLimitMiddleware(mux))))))

	// Provision /var/lib/serverpilot once, while we have root, so that
	// later `sp port` invocations from non-root deploy users (CI/CD
	// scripts) find the directory ready with the correct setgid + group
	// ownership. Failure is non-fatal: dashboard can still come up; only
	// non-root sp port would fail until the operator re-runs as root.
	if err := portalloc.EnsureSetup(); err != nil {
		log.Printf("portalloc: setup warning: %v (sp port may need root until /var/lib/serverpilot exists)", err)
	}
	portalloc.StartDetectedPortSync(log.Printf)

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

	// Configure explicit server-side timeouts. The zero-value http.Server has
	// no timeouts at all, which makes it trivially vulnerable to Slowloris
	// (CWE-400 — slow-header / slow-body resource exhaustion). Concrete values:
	//   ReadHeaderTimeout — Slowloris cap; must be small.
	//   ReadTimeout       — full request read.
	//   WriteTimeout      — generous because some endpoints stream SSE output
	//                       from long-running shell commands (apt install,
	//                       certbot, etc.). 10 minutes is conservative.
	//   IdleTimeout       — keep-alive idle cap.
	//   MaxHeaderBytes    — 16 KB; absolute cap on header section size.
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 14,
		ErrorLog:          log.Default(),
	}
	return srv.ListenAndServe()
}
