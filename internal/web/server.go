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
