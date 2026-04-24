package web

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

//go:embed static
var staticFiles embed.FS

// Server holds the web server configuration and dependencies.
type Server struct {
	config       *auth.Config
	port         int
	sessionStore *auth.SessionStore
}

// NewServer creates a new web server instance.
func NewServer(config *auth.Config, port int) *Server {
	return &Server{
		config:       config,
		port:         port,
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
	mux.Handle("/api/sites", s.authMiddleware(http.HandlerFunc(s.handleSites)))
	mux.Handle("/api/mappings", s.authMiddleware(http.HandlerFunc(s.handleMappings)))
	mux.Handle("/api/ssl/enable", s.authMiddleware(http.HandlerFunc(s.handleSSLEnable)))
	mux.Handle("/api/ssl/disable", s.authMiddleware(http.HandlerFunc(s.handleSSLDisable)))
	mux.Handle("/api/sites/create", s.authMiddleware(http.HandlerFunc(s.handleSiteCreate)))
	mux.Handle("/api/sites/enable", s.authMiddleware(http.HandlerFunc(s.handleSiteEnable)))
	mux.Handle("/api/sites/disable", s.authMiddleware(http.HandlerFunc(s.handleSiteDisable)))
	mux.Handle("/api/system", s.authMiddleware(http.HandlerFunc(s.handleSystem)))

	// Static files.
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Wrap everything with logging and recovery middleware.
	handler := RecoveryMiddleware(LoggingMiddleware(mux))

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting server on %s", addr)
	return http.ListenAndServe(addr, handler)
}
