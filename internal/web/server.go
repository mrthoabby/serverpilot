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
	mux.Handle("/api/labels", s.authMiddleware(http.HandlerFunc(s.handleLabelsGet)))
	mux.Handle("/api/labels/set", s.authMiddleware(http.HandlerFunc(s.handleLabelSet)))
	mux.Handle("/api/labels/remove", s.authMiddleware(http.HandlerFunc(s.handleLabelRemove)))
	mux.Handle("/api/version-check", s.authMiddleware(http.HandlerFunc(s.handleVersionCheck)))
	mux.Handle("/api/update", s.authMiddleware(http.HandlerFunc(s.handleUpdate)))
	mux.Handle("/api/settings", s.authMiddleware(http.HandlerFunc(s.handleSettingsGet)))
	mux.Handle("/api/settings/domain", s.authMiddleware(http.HandlerFunc(s.handleSettingsDomain)))
	mux.Handle("/api/settings/ssl-enable", s.authMiddleware(http.HandlerFunc(s.handleSettingsSSLEnable)))
	mux.Handle("/api/settings/block-insecure", s.authMiddleware(http.HandlerFunc(s.handleSettingsBlockInsecure)))

	// Static files.
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Wrap everything with logging and recovery middleware.
	handler := RecoveryMiddleware(LoggingMiddleware(mux))

	// Start the background memory history collector (snapshots every 5 min).
	sysinfo.StartHistoryCollector()

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting server on %s", addr)
	return http.ListenAndServe(addr, handler)
}
