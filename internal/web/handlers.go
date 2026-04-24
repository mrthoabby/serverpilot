package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/mapper"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/sysinfo"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

const sessionCookieName = "sp_session"

var (
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
	htmlTagRegex = regexp.MustCompile(`<[^>]*>`)
)

type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type domainRequest struct {
	Domain string `json:"domain"`
}

type siteCreateRequest struct {
	Domain       string `json:"domain"`
	TemplateType string `json:"template_type"`
	Port         int    `json:"port"`
}

// Dashboard page template.
var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>ServerPilot Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div id="app">
        <h1>ServerPilot Dashboard</h1>
        <div id="login-form">
            <h2>Login</h2>
            <form id="loginForm">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
        <div id="dashboard" style="display:none;">
            <nav>
                <button onclick="loadContainers()">Containers</button>
                <button onclick="loadSites()">Sites</button>
                <button onclick="loadMappings()">Mappings</button>
                <button onclick="logout()">Logout</button>
            </nav>
            <div id="content"></div>
        </div>
    </div>
    <script src="/static/app.js"></script>
</body>
</html>`))

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, nil); err != nil {
		log.Printf("Error rendering dashboard: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if containsHTML(req.Username) || containsHTML(req.Password) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
		return
	}

	if !auth.ValidatePassword(s.config, req.Password) || req.Username != s.config.Username {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid credentials"})
		return
	}

	token, err := auth.GenerateSessionToken()
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "internal server error"})
		return
	}

	s.sessionStore.AddSession(token, req.Username)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production behind HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "logged in"}})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.sessionStore.RemoveSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "logged out"}})
}

func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	containers, err := docker.ListContainers()
	if err != nil {
		log.Printf("Error listing containers: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list containers"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: containers})
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	sites, err := nginx.ListSites()
	if err != nil {
		log.Printf("Error listing sites: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list sites"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: sites})
}

func (s *Server) handleMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	mappings, err := mapper.MapContainersToSites()
	if err != nil {
		log.Printf("Error listing mappings: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list mappings"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: mappings})
}

func (s *Server) handleSSLEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	if err := mapper.EnableSSL(req.Domain); err != nil {
		log.Printf("Error enabling SSL for %s: %v", req.Domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to enable SSL"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "SSL enabled for " + req.Domain}})
}

func (s *Server) handleSSLDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	if err := mapper.DisableSSL(req.Domain); err != nil {
		log.Printf("Error disabling SSL for %s: %v", req.Domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to disable SSL"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "SSL disabled for " + req.Domain}})
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid port number"})
		return
	}

	tmplType := templates.TemplateType(strings.ToLower(req.TemplateType))
	if tmplType != templates.NestJS && tmplType != templates.API {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid template type; use 'nestjs' or 'api'"})
		return
	}

	if err := templates.ApplyTemplate(tmplType, req.Domain, req.Port); err != nil {
		log.Printf("Error creating site %s: %v", req.Domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to create site"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"message": "Site created for " + req.Domain,
		"port":    strconv.Itoa(req.Port),
	}})
}

func (s *Server) handleSiteEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	if err := nginx.EnableSite(req.Domain); err != nil {
		log.Printf("Error enabling site %s: %v", req.Domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to enable site"})
		return
	}

	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("Error reloading nginx: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "site enabled but failed to reload nginx"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "Site enabled: " + req.Domain}})
}

func (s *Server) handleSiteDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	if err := nginx.DisableSite(req.Domain); err != nil {
		log.Printf("Error disabling site %s: %v", req.Domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to disable site"})
		return
	}

	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("Error reloading nginx: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "site disabled but failed to reload nginx"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "Site disabled: " + req.Domain}})
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	info, err := sysinfo.Collect()
	if err != nil {
		log.Printf("Error collecting system info: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to collect system info"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: info})
}

// writeJSON sends a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// isValidDomain validates a domain string.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain) && !containsHTML(domain)
}

// containsHTML checks if a string contains HTML tags.
func containsHTML(s string) bool {
	return htmlTagRegex.MatchString(s)
}
