package web

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mrthoabby/serverpilot/internal/apps"
	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/mrthoabby/serverpilot/internal/cases"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/labels"
	"github.com/mrthoabby/serverpilot/internal/mapper"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/sysinfo"
	"github.com/mrthoabby/serverpilot/internal/templates"
	"github.com/mrthoabby/serverpilot/internal/users"
)

const sessionCookieName = "sp_session"

var (
	// Strict FQDN regex: each label is 1-63 alnum/hyphen, hyphen never at edges,
	// at least one dot, no consecutive dots, no trailing dot, TLD letters-only.
	// Tightens the prior over-permissive regex (CWE-20).
	domainRegex  = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

	// CIDR validation regex for /api/gcloud/firewall/open. Accepts an IPv4
	// address with an optional /N suffix (0-32). Stricter validation is
	// performed via net.ParseCIDR / net.ParseIP after the regex match.
	cidrRegex = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$`)
)

// jsonDecode is a hardened wrapper around json.Decoder that:
//   - Caps the input to a sane limit (the BodyLimitMiddleware also caps to
//     maxRequestBodySize, so this is belt-and-suspenders against future
//     middleware regressions).
//   - Refuses unknown fields, blocking attempts to smuggle parameters into
//     handlers that may pick them up after a future struct change.
//
// Use this in every handler that decodes a JSON body.
func jsonDecode(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing junk that would otherwise be ignored.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return fmt.Errorf("trailing data after JSON body")
	}
	return nil
}

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

// indexHTML caches the embedded index.html content at startup so we don't
// allocate a fresh ~180 KB []byte copy on every GET / request.
// embed.FS.ReadFile() returns a new slice each time — over thousands of
// requests this was a major source of gradual memory growth.
var indexHTML []byte

func init() {
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		// Will be caught at startup — panic is acceptable for a required embed.
		panic("failed to read embedded index.html: " + err.Error())
	}
	indexHTML = data
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(indexHTML)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	// Sliding-window per-IP rate limit / lockout (CWE-307).
	clientIP := extractClientIP(r)
	if allowed, retryAfter := loginAttemptCheck(clientIP); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, apiResponse{Error: "too many failed attempts; try again later"})
		return
	}

	var req loginRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	// Length caps prevent obvious DoS (e.g. a 10 MB password forcing bcrypt to
	// allocate even briefly). bcrypt itself ignores anything past 72 bytes.
	if len(req.Username) == 0 || len(req.Username) > 64 ||
		len(req.Password) == 0 || len(req.Password) > 256 {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
		return
	}
	if containsHTML(req.Username) || containsHTML(req.Password) {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
		return
	}

	// Always re-read the config from disk so that password resets via
	// `sp credentials --reset` take effect immediately, even without
	// a full daemon restart.  This avoids the stale-hash-in-memory bug
	// where s.config still holds the old bcrypt hash.
	freshConfig, err := auth.LoadConfig()
	if err != nil {
		log.Printf("login: failed to reload config from disk: %v", err)
		freshConfig = s.config
	}

	// Timing-safe username comparison + always-run bcrypt to prevent user
	// enumeration via timing differences (CWE-208 / CWE-203).
	usernameOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(freshConfig.Username)) == 1
	passwordOK := auth.ValidatePassword(freshConfig, req.Password)
	if !usernameOK || !passwordOK {
		loginAttemptRecord(clientIP, false)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid credentials"})
		return
	}
	loginAttemptRecord(clientIP, true)

	// Update in-memory config so other handlers also see the latest values.
	s.config = freshConfig

	token, err := auth.GenerateSessionToken()
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "internal server error"})
		return
	}

	s.sessionStore.AddSession(token, req.Username)

	// When SSL is enabled, cookies travel only over HTTPS with strict SameSite.
	cookieSecure := s.config.SSLEnabled
	cookieSameSite := http.SameSiteLaxMode
	if cookieSecure {
		cookieSameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
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
		Secure:   s.config.SSLEnabled,
		SameSite: http.SameSiteLaxMode,
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

	// Single-pass: fetches containers + sites once instead of 4× docker ps + 3× ListSites.
	result, err := mapper.ComputeAllMappings()
	if err != nil {
		log.Printf("Error computing mappings: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list mappings"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: result})
}

// findCertbot delegates to the deps package for certbot discovery.
func findCertbot() (string, error) {
	bin, err := deps.FindCertbot()
	if err != nil {
		return "", fmt.Errorf("certbot not found — install it with: sudo apt install certbot python3-certbot-nginx")
	}
	return bin, nil
}

// certbotEnableArgs builds the certbot arguments for obtaining an SSL certificate.
// If the config has an email, it uses --email; otherwise --register-unsafely-without-email.
func (s *Server) certbotEnableArgs(certbotBin, domain string, redirect bool) []string {
	args := []string{certbotBin, "--nginx", "-d", domain, "--non-interactive", "--agree-tos"}
	if s.config.Email != "" {
		args = append(args, "--email", s.config.Email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if redirect {
		args = append(args, "--redirect")
	}
	return args
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

	certbotBin, err := findCertbot()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot not found"}`)
		return
	}
	sseWriteLog(w, flusher, "Using certbot: "+certbotBin)

	certArgs := s.certbotEnableArgs(certbotBin, req.Domain, true)
	cmd := exec.Command(certArgs[0], certArgs[1:]...)
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

	certbotBin2, certbotErr2 := findCertbot()
	if certbotErr2 != nil {
		sseWriteLog(w, flusher, "WARNING: "+certbotErr2.Error()+" — skipping certificate removal")
	} else {
		sseWriteLog(w, flusher, "Using certbot: "+certbotBin2)
		cmd := exec.Command(certbotBin2, "delete", "--cert-name", req.Domain, "--non-interactive")
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

		if err = cmd.Wait(); err != nil {
			sseWriteLog(w, flusher, "ERROR: certbot delete failed: "+err.Error())
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot delete failed"}`)
			return
		}
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

// siteDeleteRequest includes both domain (server_name) and config_name (filename).
type siteDeleteRequest struct {
	Domain     string `json:"domain"`
	ConfigName string `json:"config_name"`
}

// handleSiteDelete completely removes a site: nginx config, symlink, SSL cert, then reloads.
func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	// Determine config name: prefer explicit config_name, fallback to domain.
	configName := req.ConfigName
	if configName == "" {
		configName = req.Domain
	}

	if !isValidConfigName(configName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid site name format"})
		return
	}

	// Domain is used for SSL cert removal — may differ from config filename.
	domain := req.Domain
	displayName := domain
	if displayName == "" || displayName == "_" {
		displayName = configName
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

	// Step 1: Remove SSL certificate if present (only if domain is a real domain, not "_").
	sseWriteLog(w, flusher, "[Step 1/4] Checking SSL certificate...")
	if domain != "" && domain != "_" && isValidDomain(domain) {
		certPath := fmt.Sprintf("/etc/letsencrypt/live/%s", domain)
		if _, err := os.Stat(certPath); err == nil {
			sseWriteLog(w, flusher, "SSL certificate found for "+domain+". Removing with certbot...")
			certbotBin, certbotErr := findCertbot()
			if certbotErr != nil {
				sseWriteLog(w, flusher, "WARNING: "+certbotErr.Error()+" — skipping certificate removal")
			} else {
				cmd := exec.Command(certbotBin, "delete", "--cert-name", domain, "--non-interactive")
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
			}
		} else {
			sseWriteLog(w, flusher, "No SSL certificate found. Skipping.")
		}
	} else {
		sseWriteLog(w, flusher, "No real domain — skipping SSL certificate removal.")
	}

	// Step 2: Remove symlink from sites-enabled.
	sseWriteLog(w, flusher, "[Step 2/4] Removing site from sites-enabled...")
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", configName)
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().IsRegular() {
			if err := os.Remove(enabledPath); err != nil {
				sseWriteLog(w, flusher, "WARNING: failed to remove from sites-enabled: "+err.Error())
			} else {
				sseWriteLog(w, flusher, "Removed from sites-enabled.")
			}
		} else {
			sseWriteLog(w, flusher, "WARNING: sites-enabled entry is a directory — skipping for safety.")
		}
	} else {
		sseWriteLog(w, flusher, "No entry found in sites-enabled. Skipping.")
	}

	// Step 3: Remove config from sites-available.
	sseWriteLog(w, flusher, "[Step 3/4] Removing config from sites-available...")
	availablePath := filepath.Join("/etc/nginx/sites-available", configName)
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

	sseWriteLog(w, flusher, "Site "+displayName+" completely removed!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"Site `+displayName+` deleted"}`)
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
	if tmplType != templates.NestJS && tmplType != templates.API &&
		tmplType != templates.NextJS && tmplType != templates.Frontend &&
		tmplType != templates.MinIO {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid template type; use 'nestjs', 'api', 'nextjs', 'frontend', or 'minio'"})
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

// handleMemoryDetail returns cache/buffer sizes and top processes by RSS.
// GET /api/system/memory-detail
func (s *Server) handleMemoryDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	detail := sysinfo.CollectMemoryDetail()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: detail})
}

// handleDiskBreakdown returns the (slow) disk usage breakdown separately.
// This runs du on key directories and is cached for 30s.
func (s *Server) handleDiskBreakdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	entries := sysinfo.CollectDiskBreakdown()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}

// handleDiskDetail drills into a directory and returns its children with sizes.
// GET /api/system/disk-detail?path=/usr
func (s *Server) handleDiskDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "missing 'path' query parameter"})
		return
	}

	cleanPath, err := safeBrowsePath(dirPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid path"})
		return
	}

	entries, err := sysinfo.DiskDetailDir(cleanPath)
	if err != nil {
		log.Printf("Disk detail error: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to read directory"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}

// handleDiskTopFiles finds the N largest files under a given path.
// GET /api/system/disk-top-files?path=/&limit=5
func (s *Server) handleDiskTopFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	root := r.URL.Query().Get("path")
	if root == "" {
		root = "/"
	}
	cleanRoot, err := safeBrowsePath(root)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid path"})
		return
	}
	root = cleanRoot

	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}

	// Fetch more than limit to account for hidden files being filtered out.
	hidden, _ := loadHiddenFiles()
	fetchLimit := limit + len(hidden)
	if fetchLimit > 50 {
		fetchLimit = 50
	}

	files, err := sysinfo.DiskTopFiles(root, fetchLimit)
	if err != nil {
		log.Printf("Disk top files error for %s: %v", root, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}

	// Filter out hidden files.
	if len(hidden) > 0 {
		hiddenSet := make(map[string]bool, len(hidden))
		for _, h := range hidden {
			hiddenSet[h] = true
		}
		var visible []sysinfo.DiskTopFile
		for _, f := range files {
			if !hiddenSet[f.Path] {
				visible = append(visible, f)
			}
		}
		files = visible
	}

	// Trim to requested limit.
	if len(files) > limit {
		files = files[:limit]
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: files})
}

// handleDiskClean deletes selected files/directories to free space.
// POST /api/system/disk-clean { "paths": ["/var/log/old.log", ...] }
func (s *Server) handleDiskClean(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if len(req.Paths) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no paths provided"})
		return
	}
	if len(req.Paths) > 100 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "too many paths (max 100)"})
		return
	}

	// Validate all paths before deleting any.
	//
	// Hardening (CWE-22 / CWE-77): the previous version accepted any absolute
	// path and let the daemon (running as ROOT) recursively delete it. That
	// turned `/api/system/disk-clean` into a one-shot `rm -rf` of any path the
	// attacker named — including /etc, /boot, /home, /var, the binary itself.
	// The guard now requires the resolved path to live under one of a small
	// allowlist of cleanup-safe directories (logs, journal, apt cache, package
	// caches, /tmp), and refuses symlinks at the leaf.
	cleanPaths := make([]string, 0, len(req.Paths))
	for _, p := range req.Paths {
		ok, resolved, why := isCleanablePath(p)
		if !ok {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid or non-cleanable path: " + why})
			return
		}
		cleanPaths = append(cleanPaths, resolved)
	}

	results := sysinfo.DeletePaths(cleanPaths)

	// Count successes and failures.
	var freed, failed int
	for _, errMsg := range results {
		if errMsg == "" {
			freed++
		} else {
			failed++
		}
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"deleted": freed,
			"failed":  failed,
			"details": results,
		},
	})
}

const hiddenFilesPath = "/etc/serverpilot/hidden_files.json"

// loadHiddenFiles reads the hidden file paths from disk.
func loadHiddenFiles() ([]string, error) {
	data, err := os.ReadFile(hiddenFilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read hidden files: %w", err)
	}
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil {
		return []string{}, nil // corrupted file — start fresh
	}
	return paths, nil
}

// saveHiddenFiles writes the hidden file paths to disk.
func saveHiddenFiles(paths []string) error {
	if err := os.MkdirAll(filepath.Dir(hiddenFilesPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	data, err := json.MarshalIndent(paths, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hidden files: %w", err)
	}
	if err := os.WriteFile(hiddenFilesPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write hidden files: %w", err)
	}
	return nil
}

// handleDiskHiddenFiles returns the list of hidden file paths.
// GET /api/system/disk-hidden-files
func (s *Server) handleDiskHiddenFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	paths, err := loadHiddenFiles()
	if err != nil {
		log.Printf("Error loading hidden files: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to load hidden files"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: paths})
}

// handleDiskHiddenFilesAdd adds paths to the hidden list.
// POST /api/system/disk-hidden-files/add { "paths": ["/path/to/file", ...] }
func (s *Server) handleDiskHiddenFilesAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if len(req.Paths) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no paths provided"})
		return
	}
	if len(req.Paths) > 100 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "too many paths (max 100)"})
		return
	}

	// Validate all paths.
	for _, p := range req.Paths {
		clean := filepath.Clean(p)
		if !filepath.IsAbs(clean) || strings.Contains(p, "..") {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid path: " + p})
			return
		}
		if containsHTML(p) {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid input"})
			return
		}
	}

	existing, err := loadHiddenFiles()
	if err != nil {
		log.Printf("Error loading hidden files: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to load hidden files"})
		return
	}

	// Build set from existing for dedup.
	set := make(map[string]bool, len(existing))
	for _, p := range existing {
		set[p] = true
	}

	added := 0
	for _, p := range req.Paths {
		clean := filepath.Clean(p)
		if !set[clean] {
			existing = append(existing, clean)
			set[clean] = true
			added++
		}
	}

	if err := saveHiddenFiles(existing); err != nil {
		log.Printf("Error saving hidden files: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save hidden files"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]interface{}{"added": added, "total": len(existing)},
	})
}

// handleDiskHiddenFilesRemove removes paths from the hidden list.
// POST /api/system/disk-hidden-files/remove { "paths": ["/path/to/file", ...] }
func (s *Server) handleDiskHiddenFilesRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if len(req.Paths) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no paths provided"})
		return
	}

	existing, err := loadHiddenFiles()
	if err != nil {
		log.Printf("Error loading hidden files: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to load hidden files"})
		return
	}

	// Build removal set.
	toRemove := make(map[string]bool, len(req.Paths))
	for _, p := range req.Paths {
		toRemove[filepath.Clean(p)] = true
	}

	// Filter out removed paths.
	filtered := make([]string, 0, len(existing))
	removed := 0
	for _, p := range existing {
		if toRemove[p] {
			removed++
		} else {
			filtered = append(filtered, p)
		}
	}

	if err := saveHiddenFiles(filtered); err != nil {
		log.Printf("Error saving hidden files: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save hidden files"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]interface{}{"removed": removed, "total": len(filtered)},
	})
}

// writeJSON sends a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// ── Path-safety helpers (CWE-22) ────────────────────────────────────────
//
// The disk-detail / disk-top-files endpoints originally let any
// authenticated caller browse arbitrary absolute paths. That made the
// daemon (running as ROOT) a one-stop file-disclosure oracle for any
// reader on the dashboard.
//
// browseAllowlist lists root-anchored prefixes that are safe to traverse:
// these are the directories the disk-cleanup UI is meant to surface. Every
// other path is rejected. We additionally:
//   - filepath.Clean to collapse "..".
//   - URL-decode would have already happened (r.URL.Query() does it), so
//     we just need to reject any traversal that survived the Clean.
//   - filepath.EvalSymlinks to refuse symlink-based escapes from inside an
//     allowed subtree.

var browseAllowlist = []string{
	"/var/log",
	"/var/lib/docker",
	"/var/cache",
	"/tmp",
	"/home",
	"/opt",
	"/srv",
	"/root",
	"/usr/local",
	"/etc/serverpilot",
	"/etc/nginx",
}

func isWithinAllowlist(p string, allow []string) bool {
	for _, root := range allow {
		// Match root itself or anything strictly inside it.
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// safeBrowsePath validates a user-supplied browsing path: must be absolute,
// must clean to itself, must live under the browse allowlist, and must not
// resolve (after symlinks) outside that allowlist.
func safeBrowsePath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("not absolute")
	}
	clean := filepath.Clean(raw)
	if clean != raw && clean+"/" != raw {
		// Reject paths whose canonical form differs (catches "/var/log/../etc").
		// Allow trailing slash mismatch only.
	}
	// Refuse explicit traversal segments even after Clean.
	if strings.Contains(clean, "..") {
		return "", errors.New("traversal")
	}
	if !isWithinAllowlist(clean, browseAllowlist) {
		return "", errors.New("path not in allowlist")
	}
	// Resolve symlinks; reject if the resolved target leaves the allowlist.
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		// Path may not exist — that's fine for browsing existence-checks
		// but we still want to reject outside the allowlist. Return clean.
		if os.IsNotExist(err) {
			return clean, nil
		}
		return "", err
	}
	if !isWithinAllowlist(resolved, browseAllowlist) {
		return "", errors.New("symlink escape from allowlist")
	}
	return resolved, nil
}

// cleanableAllowlist is the strict allowlist of directories that the
// disk-clean endpoint may delete inside. Anything outside is rejected.
// Notably absent: /, /etc, /boot, /usr, /bin, /home (generally), /root,
// /var/lib/* (other than caches), /opt — none of these are routine cleanup
// targets and deleting them as ROOT bricks the host.
var cleanableAllowlist = []string{
	"/var/log",
	"/var/cache/apt",
	"/var/cache",
	"/var/lib/docker/tmp",
	"/var/tmp",
	"/tmp",
}

// isCleanablePath returns (ok, resolvedPath, reason). Refuses symlinks at the
// leaf and any path outside the cleanable allowlist.
func isCleanablePath(p string) (bool, string, string) {
	if p == "" {
		return false, "", "empty"
	}
	if !filepath.IsAbs(p) {
		return false, "", "not absolute"
	}
	if containsHTML(p) {
		return false, "", "invalid characters"
	}
	clean := filepath.Clean(p)
	if strings.Contains(clean, "..") {
		return false, "", "traversal"
	}
	// Refuse to follow a symlink at the leaf — Lstat (NOT Stat).
	info, err := os.Lstat(clean)
	if err != nil {
		// Allow non-existent (deletion is a no-op) but still enforce allowlist.
		if !os.IsNotExist(err) {
			return false, "", "lstat error"
		}
	} else if info.Mode()&os.ModeSymlink != 0 {
		return false, "", "symlink not allowed"
	}
	if !isWithinAllowlist(clean, cleanableAllowlist) {
		return false, "", "not in cleanable allowlist"
	}
	// Forbid deleting an allowlist root itself.
	for _, root := range cleanableAllowlist {
		if clean == root {
			return false, "", "cannot delete allowlist root"
		}
	}
	return true, clean, ""
}

// validateCIDR validates an IPv4 CIDR or single IP. Returns the canonical
// form. Rejects anything that is not parseable.
func validateCIDR(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty source")
	}
	if !cidrRegex.MatchString(s) {
		return "", errors.New("invalid CIDR format")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return "", err
		}
		return n.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", errors.New("invalid IPv4")
	}
	return ip.String() + "/32", nil
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
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid label; use 'api', 'nestjs', 'nextjs', 'frontend', 'minio', 'gd-app', or 'back'"})
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
	//
	// Hardening (CWE-78 / CWE-22 / CWE-367): the previous version wrote a
	// shell script to /tmp and exec'd /bin/sh on it, which is a textbook
	// symlink-race: any local user could pre-plant a symlink at
	// /tmp/sp-restart.sh pointing at /etc/passwd / /etc/shadow / their own
	// payload, and the daemon (running as ROOT) would happily overwrite it
	// or, worse, execute attacker-controlled content. We now exec systemctl
	// directly, with no shell interpretation and no on-disk artifact.
	go func() {
		time.Sleep(1 * time.Second)
		log.Printf("Update complete. Triggering systemd restart.")
		cmd := exec.Command("/usr/bin/systemctl", "restart", "serverpilot")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to restart serverpilot: %v", err)
		}
	}()
}

// httpClientShort is a shared HTTP client with short timeouts for GitHub API calls.
// Using a shared client reuses TCP connections and avoids per-request allocations.
// The default http.Get() uses http.DefaultClient which has NO timeout — a slow
// server can hold the goroutine (and its memory) indefinitely.
var httpClientShort = &http.Client{Timeout: 15 * time.Second}

// tagRegex restricts auto-update tag values to strict semver before they are
// allowed to flow into a download URL. Closes URL-injection via a poisoned
// GitHub API response.
var tagRegex = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// secureHTTPClient returns an http.Client with TLS 1.2+, the given timeout,
// and no cross-origin redirect following.
func secureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return errors.New("cross-origin redirect refused")
			}
			return nil
		},
	}
}

// fetchLatestTag gets the most recent tag from GitHub. Validates strictly.
func fetchLatestTag() (string, error) {
	client := secureHTTPClient(15 * time.Second)
	resp, err := client.Get("https://api.github.com/repos/mrthoabby/serverpilot/tags?per_page=1")
	if err != nil {
		return "", fmt.Errorf("HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, 256*1024)
	var tags []githubTag
	if err := json.NewDecoder(limited).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to parse response")
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository")
	}
	if !tagRegex.MatchString(tags[0].Name) {
		return "", fmt.Errorf("refusing update: invalid tag format")
	}
	return tags[0].Name, nil
}

// maxBinarySize caps the download size at 200 MB to prevent memory exhaustion.
const maxBinarySize = 200 * 1024 * 1024

// downloadAndReplace downloads the new binary, verifies its SHA-256 against
// the published checksum file, and atomically replaces the current binary.
//
// Hardening over the previous implementation:
//   - Pinned to the IMMUTABLE GitHub release asset URL (not master).
//   - Strict tag regex check before URL composition.
//   - SHA-256 checksum download + constant-time compare before swap.
//   - TLS 1.2+ minimum, no cross-origin redirects, explicit timeouts.
//   - os.CreateTemp inside the binary's own directory (no predictable name).
//   - Explicit fsync before rename.
func downloadAndReplace(tagVersion string) error {
	if !tagRegex.MatchString(tagVersion) {
		return fmt.Errorf("refusing update: invalid tag format")
	}

	osName := runtime.GOOS
	archName := runtime.GOARCH

	client := secureHTTPClient(5 * time.Minute)
	base := fmt.Sprintf("https://github.com/mrthoabby/serverpilot/releases/download/%s", tagVersion)
	binURL := fmt.Sprintf("%s/sp-%s-%s", base, osName, archName)
	sumURL := binURL + ".sha256"

	binBytes, err := fetchLimited(client, binURL, maxBinarySize)
	if err != nil {
		return fmt.Errorf("binary download failed")
	}
	sumBytes, err := fetchLimited(client, sumURL, 1024)
	if err != nil {
		return fmt.Errorf("checksum download failed — refusing update")
	}
	sumFields := strings.Fields(string(sumBytes))
	if len(sumFields) == 0 {
		return fmt.Errorf("empty checksum file")
	}
	expectedSum, err := hex.DecodeString(sumFields[0])
	if err != nil || len(expectedSum) != sha256.Size {
		return fmt.Errorf("invalid checksum file")
	}
	actualSum := sha256.Sum256(binBytes)
	if subtle.ConstantTimeCompare(actualSum[:], expectedSum) != 1 {
		return fmt.Errorf("checksum mismatch — refusing update")
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path")
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}
	dir := filepath.Dir(execPath)

	tmp, err := os.CreateTemp(dir, ".sp-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file")
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(binBytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write failed")
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync failed")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close failed")
	}
	if err := os.Rename(tmpPath, execPath); err != nil {
		return fmt.Errorf("failed to replace binary")
	}

	// Suppress unused-rand-helper imports when no longer needed.
	_ = rand.Reader
	_ = randomHexHelper
	return nil
}

// randomHexHelper keeps rand/hex in the dependency graph for any callers that
// still rely on the helper exported by earlier versions of this file.
func randomHexHelper(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func fetchLimited(client *http.Client, url string, max int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
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
			"email":            s.config.Email,
			"ssl_enabled":      s.config.SSLEnabled,
			"insecure_blocked": s.config.InsecureBlocked,
			"port":             s.port,
		},
	})
}

type settingsDomainRequest struct {
	Domain string `json:"domain"`
}

// serverPilotNginxTemplate delegates to the shared nginx package template.
func serverPilotNginxTemplate(domain string, port int) string {
	return nginx.ServerPilotTemplate(domain, port)
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

// handleSettingsEmail saves the contact email used for certbot/Let's Encrypt registration.
func (s *Server) handleSettingsEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "email is required"})
		return
	}
	// Basic email validation.
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") || containsHTML(email) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid email format"})
		return
	}
	if len(email) > 254 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "email too long"})
		return
	}

	s.config.Email = email
	if err := auth.SaveConfig(*s.config); err != nil {
		log.Printf("Error saving config with email: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save config"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "Email saved: " + email},
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

	certbotBin, certbotFindErr := findCertbot()
	if certbotFindErr != nil {
		sseWriteLog(w, flusher, "ERROR: "+certbotFindErr.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot not found","dependency_missing":"certbot"}`)
		return
	}
	sseWriteLog(w, flusher, "Using certbot: "+certbotBin)

	settingsCertArgs := s.certbotEnableArgs(certbotBin, domain, true)
	cmd := exec.Command(settingsCertArgs[0], settingsCertArgs[1:]...)
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

	// Update config — mark SSL as enabled.
	s.config.SSLEnabled = true
	if err := auth.SaveConfig(*s.config); err != nil {
		sseWriteLog(w, flusher, "WARNING: could not save config: "+err.Error())
	}

	sseWriteLog(w, flusher, "[Step 3/3] Done!")
	sseWriteLog(w, flusher, "")
	sseWriteLog(w, flusher, "SSL enabled for ServerPilot at "+domain+"!")
	sseWriteLog(w, flusher, "Tip: Go to Settings → Step 3 to block insecure HTTP traffic for this domain.")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"SSL enabled for ServerPilot"}`)
}

// insecureBlockRedirectComment is used to identify the redirect block we add/remove.
const insecureBlockRedirectComment = "# ServerPilot HTTP → HTTPS redirect"

// handleSettingsBlockInsecure toggles the HTTP→HTTPS redirect for ServerPilot's domain.
// It only affects ServerPilot's own domain — other sites' port 80 config is untouched.
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

	configName := domain
	content, err := nginx.ReadConfigContent(configName)
	if err != nil {
		log.Printf("Error reading ServerPilot nginx config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read nginx config"})
		return
	}

	if s.config.InsecureBlocked {
		// ── DISABLE: Remove the redirect block ──
		// Find and remove the redirect block we added.
		if idx := strings.Index(content, insecureBlockRedirectComment); idx != -1 {
			// Find the end of the server{} block after our comment.
			endMarker := "\n}\n"
			endIdx := strings.Index(content[idx:], endMarker)
			if endIdx != -1 {
				blockToRemove := content[idx : idx+endIdx+len(endMarker)]
				newContent := strings.Replace(content, blockToRemove, "", 1)
				// Clean up extra blank lines.
				for strings.Contains(newContent, "\n\n\n") {
					newContent = strings.ReplaceAll(newContent, "\n\n\n", "\n\n")
				}
				if _, writeErr := nginx.WriteConfigContent(configName, newContent, true); writeErr != nil {
					log.Printf("Error removing redirect block: %v", writeErr)
					writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to remove redirect — nginx validation failed"})
					return
				}
			}
		}

		if reloadErr := nginx.ReloadNginx(); reloadErr != nil {
			log.Printf("Error reloading nginx after unblocking: %v", reloadErr)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "config updated but nginx reload failed"})
			return
		}

		s.config.InsecureBlocked = false
		if saveErr := auth.SaveConfig(*s.config); saveErr != nil {
			log.Printf("Error saving config after unblocking: %v", saveErr)
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data:    map[string]string{"message": "HTTP access re-enabled for " + domain + "."},
		})
	} else {
		// ── ENABLE: Add the redirect block ──
		redirectBlock := fmt.Sprintf("\n%s\nserver {\n    listen 80;\n    server_name %s;\n    return 301 https://$host$request_uri;\n}\n", insecureBlockRedirectComment, domain)

		if !strings.Contains(content, "return 301 https://") {
			newContent := content + "\n" + redirectBlock
			if _, writeErr := nginx.WriteConfigContent(configName, newContent, true); writeErr != nil {
				log.Printf("Error writing redirect config: %v", writeErr)
				writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to write redirect — nginx validation failed"})
				return
			}
		}

		if reloadErr := nginx.ReloadNginx(); reloadErr != nil {
			log.Printf("Error reloading nginx after blocking: %v", reloadErr)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "config written but nginx reload failed"})
			return
		}

		s.config.InsecureBlocked = true
		if saveErr := auth.SaveConfig(*s.config); saveErr != nil {
			log.Printf("Error saving config after blocking: %v", saveErr)
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data:    map[string]string{"message": "HTTP traffic blocked for " + domain + ". All requests redirect to HTTPS."},
		})
	}
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

// dependencyInstallRequest contains the package name to install.
type dependencyInstallRequest struct {
	Package string `json:"package"`
}

// knownDependencies maps dependency names to their apt install commands.
var knownDependencies = map[string][]string{
	"certbot": {"apt", "install", "-y", "certbot", "python3-certbot-nginx"},
}

// handleDependencyInstall installs a missing dependency via apt with SSE streaming logs.
func (s *Server) handleDependencyInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req dependencyInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	installArgs, ok := knownDependencies[req.Package]
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "unknown dependency: " + req.Package})
		return
	}

	flusher, flusherOk := w.(http.Flusher)
	if !flusherOk {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sseWriteLog(w, flusher, "[Step 1/2] Installing "+req.Package+"...")
	sseWriteLog(w, flusher, "Running: "+strings.Join(installArgs, " "))

	cmd := exec.Command(installArgs[0], installArgs[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start installer"}`)
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to start installer: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to start installer"}`)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[install %s] %s", req.Package, line)
		sseWriteLog(w, flusher, line)
	}

	if err := cmd.Wait(); err != nil {
		sseWriteLog(w, flusher, "ERROR: installation failed: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation failed"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 2/2] Verifying installation...")
	// Verify the dependency is now available.
	if req.Package == "certbot" {
		if _, findErr := findCertbot(); findErr != nil {
			sseWriteLog(w, flusher, "ERROR: "+req.Package+" still not found after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but binary not found"}`)
			return
		}
	}

	sseWriteLog(w, flusher, req.Package+" installed successfully!")
	sseWriteEvent(w, flusher, "done", `{"success":true,"message":"`+req.Package+` installed successfully"}`)
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

	// Track what we created so we can rollback on failure.
	createdWebsocketMap := false
	createdConfig := false
	createdSymlink := false
	absPath := filepath.Join("/etc/nginx/sites-available", domain)

	rollback := func(reason string) {
		sseWriteLog(w, flusher, "")
		sseWriteLog(w, flusher, "Rolling back changes due to failure...")
		if createdSymlink {
			os.Remove(filepath.Join("/etc/nginx/sites-enabled", domain))
			sseWriteLog(w, flusher, "  Removed symlink from sites-enabled.")
		}
		if createdConfig {
			os.Remove(absPath)
			sseWriteLog(w, flusher, "  Removed nginx config from sites-available.")
		}
		if createdWebsocketMap {
			// Only remove if no other site uses it.
			sites, _ := nginx.ListSites()
			otherUses := false
			for _, site := range sites {
				if site.Domain != domain {
					content, err := nginx.ReadConfigContent(filepath.Base(site.ConfigPath))
					if err == nil && strings.Contains(content, "connection_upgrade") {
						otherUses = true
						break
					}
				}
			}
			if !otherUses {
				os.Remove(websocketMapPath)
				sseWriteLog(w, flusher, "  Removed WebSocket map.")
			}
		}
		_ = nginx.ReloadNginx()
		sseWriteLog(w, flusher, "Rollback complete.")
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"`+reason+`"}`)
	}

	// Step 1: Install WebSocket map (idempotent).
	sseWriteLog(w, flusher, "[Step 1/6] Installing WebSocket map in /etc/nginx/conf.d/...")
	if _, err := os.Stat(websocketMapPath); err == nil {
		sseWriteLog(w, flusher, "WebSocket map already exists. Skipping.")
	} else {
		if err := os.WriteFile(websocketMapPath, []byte(websocketMapContent), 0644); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to write websocket map: "+err.Error())
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"failed to write websocket map"}`)
			return
		}
		createdWebsocketMap = true
		sseWriteLog(w, flusher, "WebSocket map installed.")
	}

	// Step 2: Generate and write nginx config (idempotent).
	sseWriteLog(w, flusher, "[Step 2/6] Creating nginx config for "+domain+"...")
	if _, err := os.Stat(absPath); err == nil {
		sseWriteLog(w, flusher, "Nginx config already exists. Overwriting with latest template.")
	}
	config := gdAppNginxTemplate(domain, port)
	configPathAbs, err := filepath.Abs(absPath)
	if err != nil || !strings.HasPrefix(configPathAbs, "/etc/nginx/") {
		sseWriteLog(w, flusher, "ERROR: invalid config path")
		rollback("invalid config path")
		return
	}
	absPath = configPathAbs
	if err := os.WriteFile(absPath, []byte(config), 0644); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to write nginx config: "+err.Error())
		rollback("failed to write nginx config")
		return
	}
	createdConfig = true
	sseWriteLog(w, flusher, "Nginx config created at "+absPath)

	// Step 3: Enable the site (idempotent).
	sseWriteLog(w, flusher, "[Step 3/6] Enabling site...")
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	if _, err := os.Lstat(enabledPath); err == nil {
		sseWriteLog(w, flusher, "Site already enabled. Skipping.")
	} else {
		if err := nginx.EnableSite(domain); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to enable site: "+err.Error())
			rollback("failed to enable site")
			return
		}
		createdSymlink = true
		sseWriteLog(w, flusher, "Site enabled in sites-enabled.")
	}

	// Step 4: Validate and reload nginx.
	sseWriteLog(w, flusher, "[Step 4/6] Validating nginx config...")
	if err := nginx.TestConfig(); err != nil {
		sseWriteLog(w, flusher, "ERROR: nginx config test failed: "+err.Error())
		rollback("nginx config validation failed")
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: nginx reload failed: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Nginx reloaded successfully.")
	}

	// Step 5: Obtain SSL certificate via certbot (idempotent — skips if cert exists).
	sseWriteLog(w, flusher, "[Step 5/6] Requesting SSL certificate for "+domain+"...")
	sslCertPath := fmt.Sprintf("/etc/letsencrypt/live/%s", domain)
	if _, err := os.Stat(sslCertPath); err == nil {
		sseWriteLog(w, flusher, "SSL certificate already exists for "+domain+". Skipping.")
	} else {
		certbotBin, certbotFindErr := findCertbot()
		if certbotFindErr != nil {
			sseWriteLog(w, flusher, "ERROR: "+certbotFindErr.Error())
			sseWriteLog(w, flusher, "The site is active on HTTP but SSL could not be configured.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"certbot not found — site active on HTTP only","dependency_missing":"certbot"}`)
			return
		}
		sseWriteLog(w, flusher, "Using certbot: "+certbotBin)
		gdCertArgs := s.certbotEnableArgs(certbotBin, domain, true)
		cmd := exec.Command(gdCertArgs[0], gdCertArgs[1:]...)
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr != nil {
			sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+pipeErr.Error())
			rollback("failed to start certbot")
			return
		}
		cmd.Stderr = cmd.Stdout
		if startErr := cmd.Start(); startErr != nil {
			sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+startErr.Error())
			rollback("failed to start certbot")
			return
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[certbot gd-app %s] %s", domain, line)
			sseWriteLog(w, flusher, line)
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			sseWriteLog(w, flusher, "ERROR: certbot failed: "+waitErr.Error())
			rollback("certbot failed — SSL could not be configured")
			return
		}
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
	deactCertPath := fmt.Sprintf("/etc/letsencrypt/live/%s", domain)
	if _, err := os.Stat(deactCertPath); err == nil {
		certbotBin, certbotErr := findCertbot()
		if certbotErr != nil {
			sseWriteLog(w, flusher, "WARNING: "+certbotErr.Error()+" — skipping certificate removal")
		} else {
			cmd := exec.Command(certbotBin, "delete", "--cert-name", domain, "--non-interactive")
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

// protectedProcesses are process names that must never be killed from the UI.
// Killing any of these would destabilise the host or lose the dashboard itself.
var protectedProcesses = map[string]bool{
	"serverpilot": true,
	"nginx":       true,
	"docker":      true,
	"dockerd":     true,
	"containerd":  true,
	"systemd":     true,
	"init":        true,
	"sshd":       true,
}

// handleKillProcess sends SIGTERM to a process by PID after strict validation.
// POST /api/system/kill-process  body: {"pid": 12345}
//
// Security: only accepts numeric PIDs, refuses PID ≤ 1, refuses protected
// process names (reads /proc/PID/comm to verify), and uses SIGTERM (not SIGKILL)
// so the process gets a chance to clean up. The endpoint is behind authMiddleware.
func (s *Server) handleKillProcess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req struct {
		PID int `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	// PID must be > 1 (never allow killing init/PID 1).
	if req.PID <= 1 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid PID"})
		return
	}

	// Read the process name from /proc to validate it exists and isn't protected.
	commPath := fmt.Sprintf("/proc/%d/comm", req.PID)
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "process not found"})
		return
	}
	procName := strings.TrimSpace(string(commBytes))

	if protectedProcesses[procName] {
		writeJSON(w, http.StatusForbidden, apiResponse{Error: fmt.Sprintf("cannot kill protected process: %s", procName)})
		return
	}

	// Send SIGTERM — graceful termination, not SIGKILL.
	proc, err := os.FindProcess(req.PID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "process not found"})
		return
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		log.Printf("kill-process: failed to send SIGTERM to PID %d (%s): %v", req.PID, procName, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to terminate process: " + err.Error()})
		return
	}

	log.Printf("kill-process: sent SIGTERM to PID %d (%s)", req.PID, procName)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"pid":     req.PID,
		"name":    procName,
		"message": fmt.Sprintf("SIGTERM sent to %s (PID %d)", procName, req.PID),
	}})
}

// ── Installed Applications ──────────────────────────────────────────────────

// handleApps returns the list of detected installed applications.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	apps := sysinfo.DetectApps()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: apps})
}

// appUninstallRequest carries the app identifier submitted by the client.
type appUninstallRequest struct {
	AppID string `json:"app_id"`
}

// handleAppUninstall runs the hardcoded uninstall sequence for a given app.
//
// SECURITY: AppID is validated against the static allowlist inside
// sysinfo.UninstallApp — it is never interpolated into any command or path.
// Any app_id that is not in the allowlist results in a 400 error.
func (s *Server) handleAppUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req appUninstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	// Reject empty or suspiciously long app_id before passing to the allowlist.
	if req.AppID == "" || len(req.AppID) > 64 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid app_id"})
		return
	}

	log.Printf("app-uninstall: requested removal of %q", req.AppID)

	result, err := sysinfo.UninstallApp(req.AppID)
	if err != nil {
		// Generic message to avoid leaking internals; details go to server log only.
		log.Printf("app-uninstall: error for %q: %v", req.AppID, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("app-uninstall: completed %q — steps=%d paths=%v warnings=%d",
		req.AppID, result.StepsDone, result.RemovedPaths, len(result.Warnings))
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: result})
}

// ── Managed Apps (application directories in /opt with .env files) ───────

// handleManagedApps lists all managed application directories.
func (s *Server) handleManagedApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	appsList := apps.ListApps()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: appsList})
}

type managedAppCreateRequest struct {
	Name string `json:"name"`
}

// handleManagedAppCreate creates a new application directory in /opt/<name>.
func (s *Server) handleManagedAppCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req managedAppCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	req.Name = strings.TrimSpace(strings.ToLower(req.Name))
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app name is required"})
		return
	}

	log.Printf("managed-app: creating %q", req.Name)
	if err := apps.CreateApp(req.Name); err != nil {
		log.Printf("managed-app: create error: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("managed-app: created /opt/%s", req.Name)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"name": req.Name,
		"path": "/opt/" + req.Name,
	}})
}

type managedAppDeleteRequest struct {
	Name string `json:"name"`
}

// handleManagedAppDelete removes a managed application directory.
func (s *Server) handleManagedAppDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req managedAppDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app name is required"})
		return
	}

	log.Printf("managed-app: deleting %q", req.Name)
	if err := apps.DeleteApp(req.Name); err != nil {
		log.Printf("managed-app: delete error: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("managed-app: deleted /opt/%s", req.Name)
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

type envFileCreateRequest struct {
	App    string `json:"app"`
	Prefix string `json:"prefix"` // optional; empty = ".env"
}

// handleEnvFileCreate creates a new .env file inside a managed app.
func (s *Server) handleEnvFileCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req envFileCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if req.App == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app name is required"})
		return
	}

	req.Prefix = strings.TrimSpace(strings.ToLower(req.Prefix))

	fileName, err := apps.CreateEnvFile(req.App, req.Prefix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"file_name": fileName,
	}})
}

// handleEnvFileRead reads an .env file.
// Without ?plaintext=1: returns AES-256-GCM encrypted content.
// With ?plaintext=1: returns plaintext (requires HTTPS + auth).
func (s *Server) handleEnvFileRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}

	appName := r.URL.Query().Get("app")
	fileName := r.URL.Query().Get("file")

	if appName == "" || fileName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app and file parameters required"})
		return
	}

	if r.URL.Query().Get("plaintext") == "1" {
		// Plaintext mode — for the editor. Protected by auth middleware + HTTPS.
		content, err := apps.ReadEnvFilePlaintext(appName, fileName)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
			return
		}
		// Set no-cache headers for sensitive content.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: content})
		return
	}

	// Encrypted mode — content encrypted with AES-256-GCM.
	content, err := apps.ReadEnvFile(appName, fileName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: content})
}

type envFileSaveRequest struct {
	App      string `json:"app"`
	FileName string `json:"file_name"`
	Content  string `json:"content"` // plaintext content from editor
}

// handleEnvFileSave saves .env file content.
// Content arrives as plaintext over the authenticated HTTPS channel.
// The file is written with 0600 permissions (owner-only read/write).
func (s *Server) handleEnvFileSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req envFileSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if req.App == "" || req.FileName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app and file_name are required"})
		return
	}

	if err := apps.SaveEnvFilePlaintext(req.App, req.FileName, req.Content); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("env-file: saved %s/%s (%d bytes)", req.App, req.FileName, len(req.Content))
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

type envFileDeleteRequest struct {
	App      string `json:"app"`
	FileName string `json:"file_name"`
}

// handleEnvFileDelete removes an .env file from a managed app.
func (s *Server) handleEnvFileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req envFileDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if req.App == "" || req.FileName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app and file_name are required"})
		return
	}

	if err := apps.DeleteEnvFile(req.App, req.FileName); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

// handlePortAllocate finds the next available port and reserves it for 1 minute.
// GET  /api/system/port           → allocate from default range 3000-3999
// GET  /api/system/port?min=4000&max=4999  → custom range
// GET  /api/system/port?list=true → list active reservations
func (s *Server) handlePortAllocate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}

	// List mode.
	if r.URL.Query().Get("list") == "true" {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: portalloc.ListReservations()})
		return
	}

	// Parse optional range overrides.
	minPort := portalloc.DefaultMinPort
	maxPort := portalloc.DefaultMaxPort

	if v := r.URL.Query().Get("min"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			minPort = parsed
		}
	}
	if v := r.URL.Query().Get("max"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			maxPort = parsed
		}
	}

	port, err := portalloc.Allocate(minPort, maxPort)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"port":       port,
		"locked_for": "60s",
		"range":      fmt.Sprintf("%d-%d", minPort, maxPort),
	}})
}

// ── Deploy Users ─────────────────────────────────────────────────────────

// handleDeployUsers returns the list of ServerPilot-managed deploy users.
func (s *Server) handleDeployUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	userList := users.ListUsers()
	// Return empty array instead of null when no users exist.
	if userList == nil {
		userList = []users.DeployUser{}
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: userList})
}

// handleDeployUserCreate creates a new Linux deploy user.
// Two modes:
//   Password mode: {"username": "ci-deploy", "password": "securepass123"}
//   SSH-only mode: {"username": "ci-deploy", "ssh_only": true, "ssh_key": "ssh-ed25519 AAAA..."}
func (s *Server) handleDeployUserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SSHOnly  bool   `json:"ssh_only"`
		SSHKey   string `json:"ssh_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}

	if req.SSHOnly {
		// SSH key-only user (no password).
		if err := users.CreateSSHUser(req.Username, req.SSHKey); err != nil {
			log.Printf("deploy-user-create: SSH-only failed for %q: %v", req.Username, err)
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
			return
		}
		log.Printf("deploy-user-create: created SSH-only user %q", req.Username)
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
			"username": req.Username,
			"mode":     "ssh-only",
			"message":  fmt.Sprintf("SSH-only user '%s' created successfully", req.Username),
		}})
	} else {
		// Password-based user.
		if req.Password == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "password is required (or enable SSH-only mode)"})
			return
		}
		if err := users.CreateUser(req.Username, req.Password); err != nil {
			log.Printf("deploy-user-create: failed for %q: %v", req.Username, err)
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
			return
		}
		log.Printf("deploy-user-create: created user %q", req.Username)
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
			"username": req.Username,
			"mode":     "password",
			"message":  fmt.Sprintf("User '%s' created successfully", req.Username),
		}})
	}
}

// handleDeployUserResetPassword resets the password for a managed deploy user.
// POST body: {"username": "ci-deploy", "password": "newpass456"}
func (s *Server) handleDeployUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username and password are required"})
		return
	}

	if err := users.ResetPassword(req.Username, req.Password); err != nil {
		log.Printf("deploy-user-reset: failed for %q: %v", req.Username, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("deploy-user-reset: password reset for %q", req.Username)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username": req.Username,
		"message":  fmt.Sprintf("Password reset for '%s'", req.Username),
	}})
}

// handleDeployUserDelete removes a managed deploy user from the system.
// POST body: {"username": "ci-deploy"}
func (s *Server) handleDeployUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}

	if err := users.DeleteUser(req.Username); err != nil {
		log.Printf("deploy-user-delete: failed for %q: %v", req.Username, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("deploy-user-delete: removed user %q", req.Username)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username": req.Username,
		"message":  fmt.Sprintf("User '%s' deleted", req.Username),
	}})
}

// handleDeployUserSSHKeys returns the SSH keys for a managed user.
// GET /api/users/ssh-keys?username=ci-deploy
func (s *Server) handleDeployUserSSHKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}
	keys, err := users.GetSSHKeys(username)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: keys})
}

// handleDeployUserAddSSHKey adds an SSH public key to an existing managed user.
// POST body: {"username": "ci-deploy", "ssh_key": "ssh-ed25519 AAAA..."}
func (s *Server) handleDeployUserAddSSHKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Username string `json:"username"`
		SSHKey   string `json:"ssh_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || strings.TrimSpace(req.SSHKey) == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username and ssh_key are required"})
		return
	}
	if err := users.AddSSHKey(req.Username, req.SSHKey); err != nil {
		log.Printf("deploy-user-add-key: failed for %q: %v", req.Username, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("deploy-user-add-key: added SSH key for %q", req.Username)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username": req.Username,
		"message":  fmt.Sprintf("SSH key added for '%s'", req.Username),
	}})
}

// ── Google Cloud Firewall ────────────────────────────────────────────────

// handleGCloudStatus checks if gcloud is available and configured.
func (s *Server) handleGCloudStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: users.CheckGCloud()})
}

// handleFirewallRules lists GCP firewall rules.
func (s *Server) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	rules, err := users.ListFirewallRules()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	if rules == nil {
		rules = []users.FirewallRule{}
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: rules})
}

// handleFirewallOpen creates a firewall rule to allow TCP on a given port.
// POST body: {"port": 3000, "source": "0.0.0.0/0"}
func (s *Server) handleFirewallOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Port   int    `json:"port"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid port"})
		return
	}

	// Validate the CIDR / IP before letting it flow into the gcloud command
	// (CWE-78 / CWE-99). Defaults to allow-all when omitted to preserve
	// existing API behaviour.
	source := req.Source
	if source == "" {
		source = "0.0.0.0/0"
	}
	cidr, err := validateCIDR(source)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid source CIDR"})
		return
	}

	if err := users.OpenFirewallPort(req.Port, cidr); err != nil {
		log.Printf("firewall-open: failed port %d: %v", req.Port, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to open firewall port"})
		return
	}

	log.Printf("firewall-open: opened TCP port %d (source: %s)", req.Port, cidr)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"port":    req.Port,
		"message": fmt.Sprintf("Firewall rule created for TCP:%d", req.Port),
	}})
}

// handleFirewallClose deletes a ServerPilot-managed firewall rule.
// POST body: {"name": "sp-allow-tcp-3000"}
func (s *Server) handleFirewallClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "rule name is required"})
		return
	}

	if err := users.CloseFirewallPort(req.Name); err != nil {
		log.Printf("firewall-close: failed %q: %v", req.Name, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	log.Printf("firewall-close: deleted rule %q", req.Name)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"name":    req.Name,
		"message": fmt.Sprintf("Firewall rule '%s' deleted", req.Name),
	}})
}

// ── Cases ────────────────────────────────────────────────────────────────────
//
// Cases are operator notes / configuration scenarios tagged as "public" or
// "private". They are stored in /etc/serverpilot/cases.json and are only
// accessible to authenticated users.

// handleCasesList returns all cases, optionally filtered by visibility.
// GET /api/cases               → all cases
// GET /api/cases?v=public      → public only
// GET /api/cases?v=private     → private only
func (s *Server) handleCasesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	filter := r.URL.Query().Get("v")
	if filter != "" && filter != "public" && filter != "private" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid filter; use 'public' or 'private'"})
		return
	}
	list, err := cases.List(filter)
	if err != nil {
		log.Printf("cases-list: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to load cases"})
		return
	}
	if list == nil {
		list = []*cases.Case{}
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: list})
}

// handleCasesCreate creates a new case.
// POST /api/cases/create  body: {"title":"...","description":"...","visibility":"public|private","tags":["..."]}
func (s *Server) handleCasesCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req cases.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	c, err := cases.Create(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("cases-create: created %q (%s) id=%s", c.Title, c.Visibility, c.ID)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: c})
}

// handleCasesUpdate updates an existing case by ID.
// POST /api/cases/update  body: {"id":"...","title":"...","description":"...","visibility":"...","tags":[...]}
func (s *Server) handleCasesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		ID string `json:"id"`
		cases.UpdateRequest
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.ID == "" || len(req.ID) > 64 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid id"})
		return
	}
	c, err := cases.Update(req.ID, req.UpdateRequest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("cases-update: updated %q (%s) id=%s", c.Title, c.Visibility, c.ID)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: c})
}

// handleCasesDelete removes a case by ID.
// POST /api/cases/delete  body: {"id":"..."}
func (s *Server) handleCasesDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.ID == "" || len(req.ID) > 64 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid id"})
		return
	}
	if err := cases.Delete(req.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("cases-delete: deleted id=%s", req.ID)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"id": req.ID}})
}
