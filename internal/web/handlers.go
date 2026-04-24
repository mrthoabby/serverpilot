package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Serve the embedded index.html from the static directory.
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		log.Printf("Error reading embedded index.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(data)
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
		SameSite: http.SameSiteLaxMode,
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

// ── Version Check & Self-Update Handlers ──

type githubTag struct {
	Name string `json:"name"`
}

type versionCheckResponse struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
}

func (s *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	latest, err := fetchLatestTag()
	if err != nil {
		log.Printf("Error checking latest version: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to check for updates"})
		return
	}

	current := strings.TrimPrefix(s.version, "v")
	latestClean := strings.TrimPrefix(latest, "v")

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: versionCheckResponse{
			Current:         current,
			Latest:          latestClean,
			UpdateAvailable: current != latestClean && latestClean != "",
		},
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	latest, err := fetchLatestTag()
	if err != nil {
		log.Printf("Error fetching latest tag for update: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to check for updates"})
		return
	}

	current := strings.TrimPrefix(s.version, "v")
	latestClean := strings.TrimPrefix(latest, "v")

	if current == latestClean {
		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data:    map[string]string{"message": "Already up to date (v" + current + ")"},
		})
		return
	}

	if err := downloadAndReplace(latest); err != nil {
		log.Printf("Error downloading update: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to download update"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"message": "Updated to v" + latestClean + ". Restarting...",
			"version": latestClean,
		},
	})

	// Restart the daemon in the background after responding.
	// Write a small script that waits 1s then restarts, so the HTTP response
	// has time to flush before the process goes down.
	go func() {
		script := "#!/bin/sh\nsleep 1\n/usr/bin/systemctl restart serverpilot 2>/dev/null || true\n"
		scriptPath := "/tmp/sp-restart.sh"
		if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
			log.Printf("Failed to write restart script: %v", err)
			return
		}
		log.Printf("Update complete. Triggering restart via %s", scriptPath)
		cmd := exec.Command("/bin/sh", scriptPath)
		if err := cmd.Start(); err != nil {
			log.Printf("Failed to start restart script: %v", err)
		}
	}()
}

// fetchLatestTag gets the most recent tag from GitHub.
func fetchLatestTag() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/mrthoabby/serverpilot/tags?per_page=1")
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository")
	}

	return tags[0].Name, nil
}

// downloadAndReplace downloads the new binary and atomically replaces the current one.
func downloadAndReplace(tagVersion string) error {
	osName := runtime.GOOS
	archName := runtime.GOARCH

	ver := strings.TrimPrefix(tagVersion, "v")
	downloadURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/%s/sp-%s-%s",
		ver, osName, archName,
	)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}

	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	tmpPath := execPath + ".tmp-" + hex.EncodeToString(randBytes)

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write update: %w", err)
	}
	tmpFile.Close()

	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}
