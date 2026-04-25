package web

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/labels"
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

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	images, err := docker.ListImages()
	if err != nil {
		log.Printf("Error listing images: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list images"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: images})
}

type imageDeleteRequest struct {
	IDs   []string `json:"ids"`
	Force bool     `json:"force"`
}

func (s *Server) handleImagesDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req imageDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no image IDs provided"})
		return
	}

	if len(req.IDs) > 100 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "too many images at once (max 100)"})
		return
	}

	var removed []string
	var errors []string
	for _, id := range req.IDs {
		if containsHTML(id) {
			errors = append(errors, id+": invalid ID")
			continue
		}

		var err error
		if req.Force {
			err = docker.ForceRemoveImage(id)
		} else {
			err = docker.RemoveImage(id)
		}
		if err != nil {
			errors = append(errors, id+": "+err.Error())
		} else {
			removed = append(removed, id)
		}
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"removed": removed,
			"errors":  errors,
		},
	})
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

	mapped, err := mapper.MapContainersToSites()
	if err != nil {
		log.Printf("Error listing mappings: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list mappings"})
		return
	}

	unmapped, err := mapper.GetUnmappedContainers()
	if err != nil {
		log.Printf("Error listing unmapped containers: %v", err)
		// Non-fatal: continue with empty unmapped list.
		unmapped = nil
	}

	orphaned, err := mapper.GetOrphanedSites()
	if err != nil {
		log.Printf("Error listing orphaned sites: %v", err)
		// Non-fatal: continue with empty orphaned list.
		orphaned = nil
	}

	result := map[string]interface{}{
		"mapped":             mapped,
		"unmappedContainers": unmapped,
		"orphanedSites":      orphaned,
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: result})
}

// sseWriteEvent writes an SSE event to the ResponseWriter and flushes.
func sseWriteEvent(w http.ResponseWriter, flusher http.Flusher, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	flusher.Flush()
}

// sseWriteLog writes a log-line SSE event.
func sseWriteLog(w http.ResponseWriter, flusher http.Flusher, line string) {
	escaped, _ := json.Marshal(line)
	sseWriteEvent(w, flusher, "log", string(escaped))
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sseWriteLog(w, flusher, "[Step 1/3] Requesting SSL certificate for "+req.Domain+"...")

	cmd := exec.Command("/usr/bin/certbot", "--nginx", "-d", req.Domain, "--non-interactive", "--agree-tos")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	if err := cmd.Start(); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[certbot enable %s] %s", req.Domain, line)
		sseWriteLog(w, flusher, line)
	}

	err = cmd.Wait()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: certbot failed: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot failed"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 2/3] Certificate obtained. Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
		sseWriteLog(w, flusher, "SSL certificate was installed but nginx did not reload.")
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	sseWriteLog(w, flusher, "[Step 3/3] SSL enabled for "+req.Domain+"!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"SSL enabled for `+req.Domain+`"}`)
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sseWriteLog(w, flusher, "[Step 1/3] Removing SSL certificate for "+req.Domain+"...")

	cmd := exec.Command("/usr/bin/certbot", "delete", "--cert-name", req.Domain, "--non-interactive")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[certbot disable %s] %s", req.Domain, line)
		sseWriteLog(w, flusher, line)
	}

	err = cmd.Wait()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: certbot delete failed: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot delete failed"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 2/3] Certificate removed. Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	sseWriteLog(w, flusher, "[Step 3/3] SSL disabled for "+req.Domain+"!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"SSL disabled for `+req.Domain+`"}`)
}

// handleSiteDelete completely removes a site: nginx config, symlink, SSL cert, then reloads.
func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	domain := req.Domain

	// Step 1: Remove SSL certificate if present.
	sseWriteLog(w, flusher, "[Step 1/4] Checking SSL certificate for "+domain+"...")
	certPath := fmt.Sprintf("/etc/letsencrypt/live/%s", domain)
	if _, err := os.Stat(certPath); err == nil {
		sseWriteLog(w, flusher, "SSL certificate found. Removing with certbot...")
		cmd := exec.Command("/usr/bin/certbot", "delete", "--cert-name", domain, "--non-interactive")
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			cmd.Stderr = cmd.Stdout
			if startErr := cmd.Start(); startErr == nil {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					sseWriteLog(w, flusher, scanner.Text())
				}
				if waitErr := cmd.Wait(); waitErr != nil {
					sseWriteLog(w, flusher, "WARNING: certbot delete failed: "+waitErr.Error())
				} else {
					sseWriteLog(w, flusher, "SSL certificate removed.")
				}
			} else {
				sseWriteLog(w, flusher, "WARNING: could not start certbot: "+startErr.Error())
			}
		}
	} else {
		sseWriteLog(w, flusher, "No SSL certificate found. Skipping.")
	}

	// Step 2: Remove symlink from sites-enabled.
	sseWriteLog(w, flusher, "[Step 2/4] Removing site from sites-enabled...")
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(enabledPath); err != nil {
				sseWriteLog(w, flusher, "WARNING: failed to remove symlink: "+err.Error())
			} else {
				sseWriteLog(w, flusher, "Symlink removed from sites-enabled.")
			}
		} else {
			sseWriteLog(w, flusher, "WARNING: sites-enabled entry is not a symlink — skipping for safety.")
		}
	} else {
		sseWriteLog(w, flusher, "No symlink found in sites-enabled. Skipping.")
	}

	// Step 3: Remove config from sites-available.
	sseWriteLog(w, flusher, "[Step 3/4] Removing config from sites-available...")
	availablePath := filepath.Join("/etc/nginx/sites-available", domain)
	if _, err := os.Stat(availablePath); err == nil {
		if err := os.Remove(availablePath); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to remove config: "+err.Error())
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to remove config file"}`)
			return
		}
		sseWriteLog(w, flusher, "Config file removed.")
	} else {
		sseWriteLog(w, flusher, "No config file found. Skipping.")
	}

	// Step 4: Reload nginx.
	sseWriteLog(w, flusher, "[Step 4/4] Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	sseWriteLog(w, flusher, "Site "+domain+" completely removed!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"Site `+domain+` deleted"}`)
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
	if tmplType != templates.NestJS && tmplType != templates.API && tmplType != templates.NextJS && tmplType != templates.Frontend {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid template type; use 'nestjs', 'api', 'nextjs', or 'frontend'"})
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

// isValidConfigName validates a config filename (more permissive than domain — allows underscores, tildes).
func isValidConfigName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name == "." || name == ".." || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~') {
			return false
		}
	}
	return !containsHTML(name)
}

// ── Nginx Config Editor Handlers ──

func (s *Server) handleSiteConfigRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	domain := r.URL.Query().Get("domain")
	if !isValidConfigName(domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config name"})
		return
	}

	content, err := nginx.ReadConfigContent(domain)
	if err != nil {
		log.Printf("Error reading config for %s: %v", domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read config file"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"domain":  domain,
			"content": content,
		},
	})
}

type configSaveRequest struct {
	Domain  string `json:"domain"`
	Content string `json:"content"`
	Reload  bool   `json:"reload"`
}

func (s *Server) handleSiteConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req configSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidConfigName(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config name"})
		return
	}

	if len(req.Content) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "content cannot be empty"})
		return
	}

	if len(req.Content) > 1048576 { // 1MB limit
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "config content too large"})
		return
	}

	if req.Reload {
		// Write + validate + reload
		testOutput, err := nginx.WriteConfigContent(req.Domain, req.Content, true)
		if err != nil {
			writeJSON(w, http.StatusOK, apiResponse{
				Success: false,
				Error:   "Validation failed",
				Data: map[string]string{
					"test_output": testOutput,
				},
			})
			return
		}
		// Config is valid, reload nginx.
		if err := nginx.ReloadNginx(); err != nil {
			log.Printf("Error reloading nginx after config save for %s: %v", req.Domain, err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "config saved but reload failed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data:    map[string]string{"message": "Config saved and nginx reloaded for " + req.Domain},
		})
	} else {
		// Write without validation or reload
		_, err := nginx.WriteConfigContent(req.Domain, req.Content, false)
		if err != nil {
			log.Printf("Error saving config for %s: %v", req.Domain, err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save config"})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data:    map[string]string{"message": "Config saved (without reload) for " + req.Domain},
		})
	}
}

// ── Container Labels Handlers ──

type labelSetRequest struct {
	ContainerName string `json:"container_name"`
	Label         string `json:"label"`
}

type labelRemoveRequest struct {
	ContainerName string `json:"container_name"`
}

func (s *Server) handleLabelsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	all, err := labels.GetAll()
	if err != nil {
		log.Printf("Error reading labels: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read labels"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: all})
}

func (s *Server) handleLabelSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req labelSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if containsHTML(req.ContainerName) || containsHTML(req.Label) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
		return
	}

	if req.ContainerName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_name is required"})
		return
	}

	if !labels.ValidLabel(req.Label) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid label; use 'api', 'nestjs', or 'back'"})
		return
	}

	if err := labels.Set(req.ContainerName, labels.Label(req.Label)); err != nil {
		log.Printf("Error setting label for %s: %v", req.ContainerName, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to set label"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "Label '" + req.Label + "' set for " + req.ContainerName},
	})
}

func (s *Server) handleLabelRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req labelRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if containsHTML(req.ContainerName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
		return
	}

	if req.ContainerName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_name is required"})
		return
	}

	if err := labels.Remove(req.ContainerName); err != nil {
		log.Printf("Error removing label for %s: %v", req.ContainerName, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to remove label"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "Label removed for " + req.ContainerName},
	})
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

// ── Settings Handlers ──

// handleSettingsGet returns the current ServerPilot settings (domain, SSL, insecure blocked).
func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"domain":           s.config.Domain,
			"ssl_enabled":      s.config.SSLEnabled,
			"insecure_blocked": s.config.InsecureBlocked,
			"port":             s.port,
		},
	})
}

type settingsDomainRequest struct {
	Domain string `json:"domain"`
}

// serverPilotNginxTemplate generates an nginx config for the ServerPilot dashboard itself.
func serverPilotNginxTemplate(domain string, port int) string {
	return fmt.Sprintf(`server {
    listen 80;
    server_name %s;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 10;

        # SSE streaming support (for progress modals)
        proxy_buffering off;
        proxy_cache off;
    }
}
`, domain, port)
}

// handleSettingsDomain sets the domain for ServerPilot and creates its nginx site.
func (s *Server) handleSettingsDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req settingsDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}

	// Generate and write the nginx config for ServerPilot.
	config := serverPilotNginxTemplate(req.Domain, s.port)
	configPath := filepath.Join("/etc/nginx/sites-available", req.Domain)

	absPath, err := filepath.Abs(configPath)
	if err != nil || !strings.HasPrefix(absPath, "/etc/nginx/") {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config path"})
		return
	}

	if err := os.WriteFile(absPath, []byte(config), 0644); err != nil {
		log.Printf("Error writing ServerPilot nginx config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to write nginx config"})
		return
	}

	// Enable the site.
	if err := nginx.EnableSite(req.Domain); err != nil {
		log.Printf("Error enabling ServerPilot site: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to enable site: " + err.Error()})
		return
	}

	// Reload nginx.
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("Error reloading nginx for ServerPilot domain: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "site created but nginx reload failed: " + err.Error()})
		return
	}

	// Save the domain in config.
	s.config.Domain = req.Domain
	s.config.SSLEnabled = false
	s.config.InsecureBlocked = false
	if err := auth.SaveConfig(*s.config); err != nil {
		log.Printf("Error saving config with domain: %v", err)
		// Non-fatal: the nginx site is already up.
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "Domain set to " + req.Domain + ". Nginx site created."},
	})
}

// handleSettingsSSLEnable enables SSL for the ServerPilot domain via certbot (SSE streaming).
func (s *Server) handleSettingsSSLEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	domain := s.config.Domain
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no domain configured — set domain first"})
		return
	}

	if s.config.SSLEnabled {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "SSL is already enabled"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sseWriteLog(w, flusher, "[Step 1/3] Requesting SSL certificate for "+domain+"...")

	cmd := exec.Command("/usr/bin/certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[certbot ServerPilot SSL %s] %s", domain, line)
		sseWriteLog(w, flusher, line)
	}

	if err := cmd.Wait(); err != nil {
		sseWriteLog(w, flusher, "ERROR: certbot failed: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot failed — check logs above"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 2/3] Certificate obtained. Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	// Update config.
	s.config.SSLEnabled = true
	if err := auth.SaveConfig(*s.config); err != nil {
		sseWriteLog(w, flusher, "WARNING: could not save config: "+err.Error())
	}

	sseWriteLog(w, flusher, "[Step 3/3] SSL enabled for ServerPilot at "+domain+"!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"SSL enabled for ServerPilot"}`)
}

// handleSettingsBlockInsecure modifies the nginx config to redirect all HTTP→HTTPS
// and marks it as permanently blocked.
func (s *Server) handleSettingsBlockInsecure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	domain := s.config.Domain
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no domain configured"})
		return
	}

	if !s.config.SSLEnabled {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "SSL must be enabled first"})
		return
	}

	if s.config.InsecureBlocked {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "insecure traffic is already blocked"})
		return
	}

	// Read the current nginx config.
	configName := domain
	content, err := nginx.ReadConfigContent(configName)
	if err != nil {
		log.Printf("Error reading ServerPilot nginx config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read nginx config"})
		return
	}

	// Add HTTP→HTTPS redirect block if not already present.
	redirectBlock := fmt.Sprintf(`
# HTTP → HTTPS redirect (insecure traffic blocked)
server {
    listen 80;
    server_name %s;
    return 301 https://$host$request_uri;
}
`, domain)

	// Check if redirect already exists.
	if strings.Contains(content, "return 301 https://") {
		// Already has redirect — just mark as blocked.
	} else {
		// Append redirect block to the config file.
		newContent := content + "\n" + redirectBlock
		if _, err := nginx.WriteConfigContent(configName, newContent, true); err != nil {
			log.Printf("Error writing redirect config: %v", err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to write redirect config — nginx validation failed"})
			return
		}
	}

	// Reload nginx.
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("Error reloading nginx after blocking insecure: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "config written but nginx reload failed"})
		return
	}

	// Update config.
	s.config.InsecureBlocked = true
	if err := auth.SaveConfig(*s.config); err != nil {
		log.Printf("Error saving config after blocking insecure: %v", err)
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "Insecure traffic blocked. All HTTP requests now redirect to HTTPS."},
	})
}

// ── GD-App Handlers ──

const websocketMapContent = `# Nginx WebSocket map — required for GD-App real-time collaboration
map $http_upgrade $connection_upgrade {
    default  upgrade;
    ''       close;
}
`

const websocketMapPath = "/etc/nginx/conf.d/websocket-map.conf"

// gdAppNginxTemplate generates the full nginx config for a GD-App site.
// Initially creates the HTTP-only version; certbot will add SSL.
func gdAppNginxTemplate(domain string, port int) string {
	return fmt.Sprintf(`# GD-App — Nginx Reverse Proxy (generated by ServerPilot)
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    # Security headers
    add_header X-Frame-Options           SAMEORIGIN always;
    add_header X-Content-Type-Options    nosniff    always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy   "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss: ws:; worker-src 'self' blob:;" always;

    # Upload limit (200 MB for attachments)
    client_max_body_size 200M;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript
               text/xml application/xml application/xml+rss text/javascript
               image/svg+xml application/wasm;
    gzip_min_length  1024;
    gzip_comp_level  5;
    gzip_vary        on;

    # Proxy base headers
    proxy_http_version      1.1;
    proxy_set_header Host               $host;
    proxy_set_header X-Real-IP          $remote_addr;
    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header Upgrade            $http_upgrade;
    proxy_set_header Connection         $connection_upgrade;
    proxy_connect_timeout   60s;
    proxy_send_timeout      300s;
    proxy_read_timeout      300s;

    # SSE / AI streaming (no buffering)
    location /api/worker/ {
        proxy_pass          http://127.0.0.1:%d;
        proxy_buffering     off;
        proxy_cache         off;
        proxy_read_timeout  600s;
    }

    # GraphQL subscriptions (WebSocket)
    location /graphql {
        proxy_pass          http://127.0.0.1:%d;
        proxy_buffering     off;
    }

    # WebSocket collaboration
    location /socket.io/ {
        proxy_pass          http://127.0.0.1:%d;
        proxy_buffering     off;
    }

    # Static assets — aggressive cache (hashed filenames)
    location ~* \.(js|css|woff2?|ttf|otf|eot|png|jpg|jpeg|gif|svg|ico|wasm)$ {
        proxy_pass          http://127.0.0.1:%d;
        proxy_cache_valid   200 1y;
        add_header          Cache-Control "public, max-age=31536000, immutable";
        add_header          X-Content-Type-Options nosniff always;
    }

    # Everything else
    location / {
        proxy_pass http://127.0.0.1:%d;
    }
}
`, domain, port, port, port, port, port)
}

type gdAppRequest struct {
	Domain        string `json:"domain"`
	ContainerName string `json:"container_name"`
	Port          int    `json:"port"`
}

// handleGDAppActivate does the full activation: websocket map, nginx config, enable site, certbot SSL, reload.
func (s *Server) handleGDAppActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req gdAppRequest
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	domain := req.Domain
	port := req.Port

	// Step 1: Install WebSocket map.
	sseWriteLog(w, flusher, "[Step 1/6] Installing WebSocket map in /etc/nginx/conf.d/...")
	if err := os.WriteFile(websocketMapPath, []byte(websocketMapContent), 0644); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to write websocket map: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to write websocket map"}`)
		return
	}
	sseWriteLog(w, flusher, "WebSocket map installed.")

	// Step 2: Generate and write nginx config.
	sseWriteLog(w, flusher, "[Step 2/6] Creating nginx config for "+domain+"...")
	config := gdAppNginxTemplate(domain, port)
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	absPath, err := filepath.Abs(configPath)
	if err != nil || !strings.HasPrefix(absPath, "/etc/nginx/") {
		sseWriteLog(w, flusher, "ERROR: invalid config path")
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"invalid config path"}`)
		return
	}
	if err := os.WriteFile(absPath, []byte(config), 0644); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to write nginx config: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to write nginx config"}`)
		return
	}
	sseWriteLog(w, flusher, "Nginx config created at "+absPath)

	// Step 3: Enable the site.
	sseWriteLog(w, flusher, "[Step 3/6] Enabling site...")
	if err := nginx.EnableSite(domain); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to enable site: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to enable site"}`)
		return
	}
	sseWriteLog(w, flusher, "Site enabled in sites-enabled.")

	// Step 4: Validate and reload nginx.
	sseWriteLog(w, flusher, "[Step 4/6] Validating nginx config...")
	if err := nginx.TestConfig(); err != nil {
		sseWriteLog(w, flusher, "ERROR: nginx config test failed: "+err.Error())
		sseWriteLog(w, flusher, "Cleaning up...")
		os.Remove(filepath.Join("/etc/nginx/sites-enabled", domain))
		os.Remove(absPath)
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"nginx config validation failed"}`)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	// Step 5: Obtain SSL certificate via certbot.
	sseWriteLog(w, flusher, "[Step 5/6] Requesting SSL certificate for "+domain+"...")
	cmd := exec.Command("/usr/bin/certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos", "--redirect")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start certbot"}`)
		return
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[certbot gd-app %s] %s", domain, line)
		sseWriteLog(w, flusher, line)
	}
	if err := cmd.Wait(); err != nil {
		sseWriteLog(w, flusher, "ERROR: certbot failed: "+err.Error())
		sseWriteLog(w, flusher, "The site is active on HTTP but SSL could not be configured.")
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot failed — site is active on HTTP only"}`)
		return
	}

	// Step 6: Final reload.
	sseWriteLog(w, flusher, "[Step 6/6] Final nginx reload...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: final reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded.")
	}

	sseWriteLog(w, flusher, "")
	sseWriteLog(w, flusher, "GD-App site activated for "+domain+" with SSL, WebSocket, SSE, and security headers!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"GD-App activated for `+domain+`"}`)
}

// handleGDAppDeactivate removes everything: SSL cert, nginx config, symlink, websocket map, reloads.
func (s *Server) handleGDAppDeactivate(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	domain := req.Domain

	// Step 1: Remove SSL certificate.
	sseWriteLog(w, flusher, "[Step 1/5] Removing SSL certificate for "+domain+"...")
	certPath := fmt.Sprintf("/etc/letsencrypt/live/%s", domain)
	if _, err := os.Stat(certPath); err == nil {
		cmd := exec.Command("/usr/bin/certbot", "delete", "--cert-name", domain, "--non-interactive")
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			cmd.Stderr = cmd.Stdout
			if startErr := cmd.Start(); startErr == nil {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					sseWriteLog(w, flusher, scanner.Text())
				}
				if waitErr := cmd.Wait(); waitErr != nil {
					sseWriteLog(w, flusher, "WARNING: certbot delete failed: "+waitErr.Error())
				} else {
					sseWriteLog(w, flusher, "SSL certificate removed.")
				}
			}
		}
	} else {
		sseWriteLog(w, flusher, "No SSL certificate found. Skipping.")
	}

	// Step 2: Remove symlink from sites-enabled.
	sseWriteLog(w, flusher, "[Step 2/5] Removing from sites-enabled...")
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			os.Remove(enabledPath)
			sseWriteLog(w, flusher, "Symlink removed.")
		} else {
			sseWriteLog(w, flusher, "WARNING: not a symlink — skipping for safety.")
		}
	} else {
		sseWriteLog(w, flusher, "No symlink found. Skipping.")
	}

	// Step 3: Remove config from sites-available.
	sseWriteLog(w, flusher, "[Step 3/5] Removing config from sites-available...")
	availablePath := filepath.Join("/etc/nginx/sites-available", domain)
	if _, err := os.Stat(availablePath); err == nil {
		if err := os.Remove(availablePath); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to remove config: "+err.Error())
		} else {
			sseWriteLog(w, flusher, "Config file removed.")
		}
	} else {
		sseWriteLog(w, flusher, "No config file found. Skipping.")
	}

	// Step 4: Check if websocket map is still needed by other sites.
	sseWriteLog(w, flusher, "[Step 4/5] Checking WebSocket map...")
	// Only remove if no other gd-app sites exist.
	sites, _ := nginx.ListSites()
	otherGDApps := false
	for _, site := range sites {
		if site.Domain != domain {
			// Check if any remaining site uses websocket upgrade.
			content, err := nginx.ReadConfigContent(filepath.Base(site.ConfigPath))
			if err == nil && strings.Contains(content, "connection_upgrade") {
				otherGDApps = true
				break
			}
		}
	}
	if !otherGDApps {
		if _, err := os.Stat(websocketMapPath); err == nil {
			os.Remove(websocketMapPath)
			sseWriteLog(w, flusher, "WebSocket map removed (no other sites need it).")
		}
	} else {
		sseWriteLog(w, flusher, "WebSocket map kept (other sites still use it).")
	}

	// Step 5: Reload nginx.
	sseWriteLog(w, flusher, "[Step 5/5] Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	sseWriteLog(w, flusher, "")
	sseWriteLog(w, flusher, "GD-App site "+domain+" completely deactivated!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"GD-App deactivated for `+domain+`"}`)
}
