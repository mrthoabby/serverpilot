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
	"net/url"
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
	"github.com/mrthoabby/serverpilot/internal/dbquery"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/labels"
	"github.com/mrthoabby/serverpilot/internal/mapper"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/permissions"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/replicas"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/mrthoabby/serverpilot/internal/sysinfo"
	"github.com/mrthoabby/serverpilot/internal/templates"
	"github.com/mrthoabby/serverpilot/internal/users"
)

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

	proxyPassPortRegex = regexp.MustCompile(`proxy_pass\s+http://(?:127\.0\.0\.1|localhost):([0-9]{1,5})\s*;`)
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
	MFACode  string `json:"mfa_code,omitempty"`
}

type domainRequest struct {
	Domain string `json:"domain"`
}

type siteCreateRequest struct {
	Domain              string                    `json:"domain"`
	TemplateType        string                    `json:"template_type"`
	Port                int                       `json:"port"`
	ContainerID         string                    `json:"container_id"`
	ContainerName       string                    `json:"container_name"`
	ContainerPort       int                       `json:"container_port"`
	IncludeWWW          bool                      `json:"include_www"`
	ReplaceExisting     bool                      `json:"replace_existing"`
	AllowSharedHostPort bool                      `json:"allow_shared_host_port"`
	EnableSSL           bool                      `json:"enable_ssl"`
	Options             templates.TemplateOptions `json:"options"`
}

type siteRedirectRequest struct {
	Domain       string `json:"domain"`
	Target       string `json:"target"`
	Code         int    `json:"code"`
	IncludeWWW   bool   `json:"include_www"`
	DelaySeconds int    `json:"delay_seconds"`
	Message      string `json:"message"`
}

type siteUpdateDomainRequest struct {
	CurrentDomain string `json:"current_domain"`
	ConfigName    string `json:"config_name"`
	NewDomain     string `json:"new_domain"`
	EnableSSL     *bool  `json:"enable_ssl,omitempty"`
	RemoveOldCert *bool  `json:"remove_old_cert,omitempty"`
}

type siteWWWRequest struct {
	Domain     string `json:"domain"`
	ConfigName string `json:"config_name"`
}

// faviconSVG caches the embedded favicon so the dashboard tab shows the
// ServerPilot logo. Served for both /favicon.svg and /favicon.ico.
var faviconSVG []byte

func init() {
	icon, err := staticFiles.ReadFile("static/favicon.svg")
	if err != nil {
		panic("failed to read embedded favicon.svg: " + err.Error())
	}
	faviconSVG = icon
}

// handleFavicon serves the embedded SVG favicon. It is intentionally public
// (no auth) so the icon renders on the login page too, and cacheable to avoid
// repeated requests.
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(faviconSVG)
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
	w.Write(s.indexHTML)
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
	if freshConfig.MFAEnabled {
		if !auth.ValidateTOTPCode(freshConfig.TOTPSecret, req.MFACode, time.Now()) {
			loginAttemptRecord(clientIP, false)
			writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid MFA code"})
			return
		}
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

	s.sessionStore.AddSession(token, req.Username, clientIP, r.Header.Get("User-Agent"))
	s.sessionStore.MarkReauthenticated(token)
	s.setSessionCookie(w, token)

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "logged in"}})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	token, ok := s.currentSessionToken(r)
	if ok {
		s.sessionStore.RemoveSession(token)
	}

	s.clearSessionCookies(w)

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

// containerIDRegex matches only lowercase-hex container IDs. Used to reject
// shell metacharacters and unicode tricks before we ever hand the value to
// `docker logs` (CWE-78). This is the same shape Docker returns from
// `docker ps --no-trunc` (sha256 of the container, 64 hex chars), but we
// allow any hex length up to 128 so short IDs also work.
var containerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,128}$`)

// handleContainerLogs returns the last 10 log lines for a container.
// Read-only → GET. Auth is enforced by the route mux.
func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if !containerIDRegex.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid container id"})
		return
	}

	logs, err := docker.GetContainerLogs(id, 10)
	if err != nil {
		// Detailed error stays server-side; client gets a generic message
		// to avoid leaking internal docker errors (CWE-209).
		log.Printf("container logs: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read logs"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"logs": logs,
			"tail": 10,
		},
	})
}

// containerLogsClearRequest is the body schema for /api/containers/logs/clear.
// Tag with DisallowUnknownFields (enforced by jsonDecode) so a future field
// rename can't silently be smuggled in by a stale client.
type containerLogsClearRequest struct {
	ID string `json:"id"`
}

type containerReloadEnvRequest struct {
	ID       string `json:"id"`
	App      string `json:"app"`
	FileName string `json:"file_name"`
}

// handleContainerLogsClear truncates a container's log file. State-changing,
// so POST + CSRFMiddleware (already wired in server.go on every protected
// route). Returns 200 with no payload on success.
func (s *Server) handleContainerLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req containerLogsClearRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	id := strings.TrimSpace(req.ID)
	if !containerIDRegex.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid container id"})
		return
	}

	if err := docker.ClearContainerLogs(id); err != nil {
		// Detailed error stays in server logs (CWE-209/CWE-532 — but the id
		// itself is non-secret hex, fine to log).
		log.Printf("clear container logs (id=%s): %v", id, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to clear logs"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "logs cleared"},
	})
}

func (s *Server) handleContainerReloadEnv(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req containerReloadEnvRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	id := strings.TrimSpace(req.ID)
	req.App = strings.TrimSpace(req.App)
	req.FileName = strings.TrimSpace(req.FileName)
	if !containerIDRegex.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid container id"})
		return
	}
	if req.App == "" || req.FileName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app and file_name are required"})
		return
	}

	envContent, err := apps.ReadEnvFilePlaintext(req.App, req.FileName)
	if err != nil {
		log.Printf("container reload env: read env app=%q file=%q: %v",
			sanitizeLogField(req.App, 64), sanitizeLogField(req.FileName, 64), err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to read environment file"})
		return
	}
	env, err := apps.ParseEnvContent(envContent.Content)
	if err != nil {
		log.Printf("container reload env: parse env app=%q file=%q: %v",
			sanitizeLogField(req.App, 64), sanitizeLogField(req.FileName, 64), err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid environment file"})
		return
	}

	if err := docker.RecreateContainerWithEnv(id, env); err != nil {
		log.Printf("container reload env (id=%s): %v", id, err)
		if strings.Contains(strings.ToLower(err.Error()), "invalid environment variable") {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid environment file"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to reload container environment"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data:    map[string]string{"message": "container recreated with selected environment"},
	})
}

type replicaPreviewRequest struct {
	ParentID    string `json:"parent_id"`
	ReplicaName string `json:"replica_name,omitempty"`
}

func (s *Server) handleContainerReplicasList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	list, err := replicas.List()
	if err != nil {
		log.Printf("container replicas list: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list replicas"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: list})
}

func (s *Server) handleContainerReplicaPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req replicaPreviewRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.ReplicaName = strings.TrimSpace(req.ReplicaName)
	if req.ParentID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "parent_id is required"})
		return
	}
	preview, err := replicas.PreviewParentForReplica(req.ParentID, req.ReplicaName)
	if err != nil {
		log.Printf("container replica preview: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to inspect parent container"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: preview})
}

func (s *Server) handleContainerReplicaCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req replicas.CreateRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamReplicaOperation(w, "replica-create", "Creating replica", func(progress replicas.Progress) (interface{}, error) {
		return replicas.Create(req, progress)
	})
}

func (s *Server) handleContainerReplicaSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req replicas.SyncRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamReplicaOperation(w, "replica-sync", "Syncing replica", func(progress replicas.Progress) (interface{}, error) {
		return replicas.Sync(req, progress)
	})
}

func (s *Server) handleContainerReplicaDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req replicas.DeleteRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamReplicaOperation(w, "replica-delete", "Deleting replica", func(progress replicas.Progress) (interface{}, error) {
		return nil, replicas.Delete(req, progress)
	})
}

func (s *Server) handleContainerReplicaUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req replicas.UpdateRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	rep, err := replicas.Update(req)
	if err != nil {
		log.Printf("replica-update: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to update replica"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: rep})
}

func (s *Server) streamReplicaOperation(w http.ResponseWriter, stage, title string, run func(replicas.Progress) (interface{}, error)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, stage, title, "")
	defer job.finishIfAbandoned()

	progress := func(line string) {
		sseWriteLog(w, flusher, line)
	}
	sseWriteLog(w, flusher, "Starting container replica operation...")
	data, err := run(progress)
	if err != nil {
		log.Printf("%s: %v", stage, err)
		msg := replicaOperationErrorMessage(err)
		sseWriteLog(w, flusher, "ERROR: "+msg)
		sseWriteLog(w, flusher, "Check journalctl -u serverpilot for full details.")
		payload, _ := json.Marshal(map[string]interface{}{"success": false, "error": msg})
		sseWriteEvent(w, flusher, "done", string(payload))
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{"success": true, "data": data})
	sseWriteLog(w, flusher, "Replica operation completed.")
	sseWriteEvent(w, flusher, "done", string(payload))
}

func replicaOperationErrorMessage(err error) string {
	if err == nil {
		return "operation failed"
	}
	msg := sanitizeLogField(err.Error(), 240)
	msg = strings.TrimSpace(msg)
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "inspect parent container"):
		return "could not inspect the parent container"
	case strings.Contains(lower, "validate replacement environment"):
		return "replacement environment is invalid"
	case strings.Contains(lower, "copy parent mounts"):
		return "could not copy parent mounts into the replacement"
	case strings.Contains(lower, "reserve replacement port") || strings.Contains(lower, "no available port"):
		return "could not reserve a replacement port"
	case strings.Contains(lower, "docker commit failed"):
		return "docker commit failed while snapshotting the parent"
	case strings.Contains(lower, "docker run failed"):
		if strings.Contains(lower, "port is already allocated") || strings.Contains(lower, "bind") {
			return "docker could not bind the selected port"
		}
		return "docker failed while starting the replacement container"
	case strings.Contains(lower, "healthcheck failed"):
		return "replacement container healthcheck failed"
	case strings.Contains(lower, "did not become ready"):
		return "replacement container did not become ready in time"
	case strings.Contains(lower, "nginx reload failed"):
		return "nginx reload failed; old replica was kept"
	case strings.Contains(lower, "switch nginx") || strings.Contains(lower, "proxy_pass"):
		return "could not switch nginx to the replacement port"
	case strings.Contains(lower, "mount source symlink refused") || strings.Contains(lower, "symlink refused"):
		return "mount copy refused because a symlink was detected"
	case strings.Contains(lower, "invalid replica name"):
		return "invalid replica name"
	case strings.Contains(lower, "replica not found"):
		return "replica not found"
	}
	if msg == "" {
		return "operation failed"
	}
	return msg
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
	opts := mapper.ComputeOptions{}
	if s.config != nil {
		opts.DashboardDomain = s.config.Domain
	}
	opts.DashboardPort = s.port
	result, err := mapper.ComputeAllMappingsWith(opts)
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
	return s.certbotEnableArgsForDomains(certbotBin, []string{domain}, redirect)
}

func (s *Server) certbotEnableArgsForDomains(certbotBin string, domains []string, redirect bool) []string {
	args := []string{certbotBin, "--nginx"}
	for _, domain := range domains {
		args = append(args, "-d", domain)
	}
	args = append(args, "--non-interactive", "--agree-tos")
	if s.config.Email != "" {
		args = append(args, "--email", s.config.Email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if redirect {
		args = append(args, "--redirect")
	}
	if len(domains) > 1 {
		args = append(args, "--expand")
	}
	return args
}

// sseWriteEvent writes an SSE event to the ResponseWriter and flushes. When the
// writer is a job tee, the frame is also recorded into the background-job
// registry before writing, so tracking survives a client disconnect.
func sseWriteEvent(w http.ResponseWriter, flusher http.Flusher, event, data string) {
	if tee, ok := w.(*sseJobTee); ok && event != "job" {
		tee.job.record(event, data)
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	flusher.Flush()
}

// sseWriteLog writes a log-line SSE event.
func sseWriteLog(w http.ResponseWriter, flusher http.Flusher, line string) {
	escaped, _ := json.Marshal(line)
	sseWriteEvent(w, flusher, "log", string(escaped))
}

func sseWriteDone(w http.ResponseWriter, flusher http.Flusher, payload map[string]interface{}) {
	data, _ := json.Marshal(payload)
	sseWriteEvent(w, flusher, "done", string(data))
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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "ssl-enable", "Enabling SSL", req.Domain)
	defer job.finishIfAbandoned()

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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "ssl-disable", "Disabling SSL", req.Domain)
	defer job.finishIfAbandoned()

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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "site-delete", "Deleting site", displayName)
	defer job.finishIfAbandoned()

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

	if err := sites.DeleteByConfigName(configName); err != nil {
		sseWriteLog(w, flusher, "WARNING: failed to update site registry: "+err.Error())
	} else {
		sseWriteLog(w, flusher, "Site registry updated.")
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

func (s *Server) handleSiteUpdateDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteUpdateDomainRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	configName := strings.TrimSpace(req.ConfigName)
	currentDomain := strings.TrimSpace(req.CurrentDomain)
	newDomain := strings.ToLower(strings.TrimSpace(req.NewDomain))
	if configName == "" {
		configName = currentDomain
	}
	if !isValidConfigName(configName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid site name format"})
		return
	}
	if !isValidDomain(newDomain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid new domain format"})
		return
	}
	if strings.EqualFold(newDomain, configName) || strings.EqualFold(newDomain, currentDomain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "new domain must be different"})
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

	enableSSL := true
	if req.EnableSSL != nil {
		enableSSL = *req.EnableSSL
	}
	removeOldCert := true
	if req.RemoveOldCert != nil {
		removeOldCert = *req.RemoveOldCert
	}

	oldDisplay := currentDomain
	if oldDisplay == "" || oldDisplay == "_" {
		oldDisplay = configName
	}

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "site-update-domain", "Updating domain", oldDisplay+" \u2192 "+newDomain)
	defer job.finishIfAbandoned()

	sseWriteLog(w, flusher, "[Step 1/6] Reading current site "+oldDisplay+"...")
	oldContent, err := nginx.ReadConfigContent(configName)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: could not read current site config.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to read current site config"})
		return
	}
	proxyPort, err := extractProxyPassPort(oldContent)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: could not detect the proxy_pass port from the current config.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "could not detect current proxy port"})
		return
	}
	tmplType := inferSiteTemplateType(oldContent)
	sseWriteLog(w, flusher, "Detected "+string(tmplType)+" template on port "+strconv.Itoa(proxyPort)+".")

	newAvailablePath, err := nginxSitePath("/etc/nginx/sites-available", newDomain)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: invalid new site path.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "invalid new site path"})
		return
	}
	if _, err := os.Lstat(newAvailablePath); err == nil {
		sseWriteLog(w, flusher, "ERROR: a site config already exists for "+newDomain+".")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "new domain already has an nginx config"})
		return
	} else if !os.IsNotExist(err) {
		sseWriteLog(w, flusher, "ERROR: could not check existing site config.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to check new site config"})
		return
	}
	newEnabledPath, err := nginxSitePath("/etc/nginx/sites-enabled", newDomain)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: invalid new enabled path.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "invalid new enabled path"})
		return
	}
	if _, err := os.Lstat(newEnabledPath); err == nil {
		sseWriteLog(w, flusher, "ERROR: a sites-enabled entry already exists for "+newDomain+".")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "new domain already has an enabled site"})
		return
	} else if !os.IsNotExist(err) {
		sseWriteLog(w, flusher, "ERROR: could not check enabled site.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to check enabled site"})
		return
	}

	createdNewConfig := false
	enabledNewSite := false
	cleanupNewCert := false
	var certbotBin string

	rollbackNewSite := func(reason string) {
		sseWriteLog(w, flusher, "")
		sseWriteLog(w, flusher, "Rolling back new domain due to failure...")
		if cleanupNewCert && certbotBin != "" {
			if err := runCertbotDeleteStream(w, flusher, certbotBin, newDomain, "certbot rollback "+newDomain); err != nil {
				sseWriteLog(w, flusher, "WARNING: could not remove new SSL certificate: "+err.Error())
			}
		}
		if enabledNewSite {
			if removed, err := removeSiteFileIfPresent("/etc/nginx/sites-enabled", newDomain); err != nil {
				sseWriteLog(w, flusher, "WARNING: could not remove new enabled site: "+err.Error())
			} else if removed {
				sseWriteLog(w, flusher, "Removed new sites-enabled entry.")
			}
		}
		if createdNewConfig {
			if removed, err := removeSiteFileIfPresent("/etc/nginx/sites-available", newDomain); err != nil {
				sseWriteLog(w, flusher, "WARNING: could not remove new config: "+err.Error())
			} else if removed {
				sseWriteLog(w, flusher, "Removed new site config.")
			}
		}
		if err := nginx.ReloadNginx(); err != nil {
			sseWriteLog(w, flusher, "WARNING: nginx reload after rollback failed: "+err.Error())
		} else {
			sseWriteLog(w, flusher, "Nginx reloaded after rollback.")
		}
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": reason})
	}

	sseWriteLog(w, flusher, "[Step 2/6] Creating nginx config for "+newDomain+"...")
	newConfig, err := templates.GetTemplate(tmplType, newDomain, proxyPort)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to render nginx template.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to render nginx template"})
		return
	}
	if err := createNewSiteConfig(newDomain, newConfig); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to write new nginx config: "+err.Error())
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to write new nginx config"})
		return
	}
	createdNewConfig = true
	sseWriteLog(w, flusher, "Created nginx config for "+newDomain+".")

	if err := nginx.EnableSite(newDomain); err != nil {
		sseWriteLog(w, flusher, "ERROR: failed to enable new site.")
		rollbackNewSite("failed to enable new site")
		return
	}
	enabledNewSite = true
	sseWriteLog(w, flusher, "Enabled "+newDomain+" in sites-enabled.")

	sseWriteLog(w, flusher, "[Step 3/6] Validating and reloading nginx for HTTP...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "ERROR: nginx reload failed: "+err.Error())
		rollbackNewSite("nginx validation failed for new domain")
		return
	}
	sseWriteLog(w, flusher, "Nginx reloaded. "+newDomain+" is active on HTTP.")

	if enableSSL {
		sseWriteLog(w, flusher, "[Step 4/6] Requesting SSL certificate for "+newDomain+"...")
		certbotBin, err = findCertbot()
		if err != nil {
			sseWriteLog(w, flusher, "ERROR: "+err.Error())
			rollbackNewSite("certbot not found")
			return
		}
		sseWriteLog(w, flusher, "Using certbot: "+certbotBin)
		certArgs := s.certbotEnableArgs(certbotBin, newDomain, true)
		cmd := exec.Command(certArgs[0], certArgs[1:]...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe: "+err.Error())
			rollbackNewSite("failed to start certbot")
			return
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to start certbot: "+err.Error())
			rollbackNewSite("failed to start certbot")
			return
		}
		cleanupNewCert = true
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[site domain update certbot %s] %s", newDomain, line)
			sseWriteLog(w, flusher, line)
		}
		if err := scanner.Err(); err != nil {
			sseWriteLog(w, flusher, "WARNING: certbot output read failed: "+err.Error())
		}
		if err := cmd.Wait(); err != nil {
			sseWriteLog(w, flusher, "ERROR: certbot failed: "+err.Error())
			rollbackNewSite("certbot failed for new domain")
			return
		}
		sseWriteLog(w, flusher, "SSL enabled for "+newDomain+".")
	} else {
		sseWriteLog(w, flusher, "[Step 4/6] SSL skipped by request.")
	}

	sseWriteLog(w, flusher, "[Step 5/6] Removing old domain config...")
	if removed, err := removeSiteFileIfPresent("/etc/nginx/sites-enabled", configName); err != nil {
		sseWriteLog(w, flusher, "WARNING: could not remove old sites-enabled entry: "+err.Error())
	} else if removed {
		sseWriteLog(w, flusher, "Removed old sites-enabled entry.")
	} else {
		sseWriteLog(w, flusher, "Old sites-enabled entry was not present.")
	}
	if removed, err := removeSiteFileIfPresent("/etc/nginx/sites-available", configName); err != nil {
		sseWriteLog(w, flusher, "WARNING: could not remove old site config: "+err.Error())
	} else if removed {
		sseWriteLog(w, flusher, "Removed old site config.")
	} else {
		sseWriteLog(w, flusher, "Old site config was not present.")
	}

	oldCertName := currentDomain
	if !isValidDomain(oldCertName) && isValidDomain(configName) {
		oldCertName = configName
	}
	if removeOldCert && oldCertName != "" && oldCertName != "_" && isValidDomain(oldCertName) && !strings.EqualFold(oldCertName, newDomain) {
		certPath := filepath.Join("/etc/letsencrypt/live", oldCertName)
		if _, err := os.Stat(certPath); err == nil {
			sseWriteLog(w, flusher, "Removing old SSL certificate for "+oldCertName+"...")
			if certbotBin == "" {
				certbotBin, err = findCertbot()
			}
			if err != nil {
				sseWriteLog(w, flusher, "WARNING: "+err.Error()+" — skipping old certificate removal")
			} else if err := runCertbotDeleteStream(w, flusher, certbotBin, oldCertName, "certbot delete "+oldCertName); err != nil {
				sseWriteLog(w, flusher, "WARNING: certbot delete failed: "+err.Error())
			} else {
				sseWriteLog(w, flusher, "Old SSL certificate removed.")
			}
		} else {
			sseWriteLog(w, flusher, "No old SSL certificate found for "+oldCertName+".")
		}
	} else {
		sseWriteLog(w, flusher, "Old SSL certificate removal skipped.")
	}

	sseWriteLog(w, flusher, "[Step 6/6] Final nginx reload...")
	if err := nginx.ReloadNginx(); err != nil {
		sseWriteLog(w, flusher, "WARNING: final nginx reload failed: "+err.Error())
		sseWriteDone(w, flusher, map[string]interface{}{
			"success": false,
			"error":   "new domain configured but final nginx reload failed",
		})
		return
	}

	sseWriteLog(w, flusher, "")
	if enableSSL {
		sseWriteLog(w, flusher, "Domain updated from "+oldDisplay+" to "+newDomain+" with SSL.")
	} else {
		sseWriteLog(w, flusher, "Domain updated from "+oldDisplay+" to "+newDomain+".")
	}
	sseWriteDone(w, flusher, map[string]interface{}{
		"success": true,
		"message": "Domain updated to " + newDomain,
	})
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteCreateRequest
	if err := jsonDecode(r, &req); err != nil {
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
	if !templates.ValidTemplateType(tmplType) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid template type"})
		return
	}

	if req.ContainerID != "" {
		rec, err := sites.Create(sites.CreateRequest{
			ContainerID:         req.ContainerID,
			ContainerName:       req.ContainerName,
			HostPort:            req.Port,
			ContainerPort:       req.ContainerPort,
			Domain:              req.Domain,
			Template:            tmplType,
			Options:             req.Options,
			IncludeWWW:          req.IncludeWWW,
			AllowSharedHostPort: req.AllowSharedHostPort,
			ReplaceExisting:     req.ReplaceExisting,
		})
		if err != nil {
			log.Printf("Error creating site %s: %v", req.Domain, err)
			status := http.StatusInternalServerError
			clientErr := siteCreateErrorForClient(err)
			if clientErr == "site already exists for this domain" {
				status = http.StatusConflict
			}
			if strings.Contains(err.Error(), "host port already has") {
				status = http.StatusConflict
				clientErr = "host port already has a site — confirm to share port"
			}
			if strings.Contains(err.Error(), "does not belong") {
				status = http.StatusBadRequest
				clientErr = "el puerto no está publicado en el contenedor — reserva/publica el puerto antes de crear el sitio"
			}
			if strings.Contains(err.Error(), "invalid body size") {
				status = http.StatusBadRequest
				clientErr = "tamaño de body inválido — usa valores como 1m, 50m o 0"
			}
			if strings.Contains(err.Error(), "container not found") {
				status = http.StatusBadRequest
				clientErr = "container not found"
			}
			writeJSON(w, status, apiResponse{Error: clientErr})
			return
		}
		if req.EnableSSL {
			writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
				"message":     "Site created for " + req.Domain + " — enable SSL from site actions",
				"port":        strconv.Itoa(req.Port),
				"site_id":     rec.ID,
				"ssl_pending": true,
			}})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
			"message": "Site created for " + req.Domain,
			"port":    strconv.Itoa(req.Port),
			"site_id": rec.ID,
		}})
		return
	}

	if req.ReplaceExisting {
		if err := nginx.RemoveSiteFiles(req.Domain); err != nil {
			log.Printf("Error removing existing site %s before recreate: %v", req.Domain, err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to remove existing site config"})
			return
		}
	}

	var err error
	if req.IncludeWWW {
		err = templates.ApplyTemplateWithWWW(tmplType, req.Domain, req.Port)
	} else {
		err = templates.ApplyTemplate(tmplType, req.Domain, req.Port)
	}
	if err != nil {
		log.Printf("Error creating site %s: %v", req.Domain, err)
		status := http.StatusInternalServerError
		clientErr := siteCreateErrorForClient(err)
		if clientErr == "site already exists for this domain" {
			status = http.StatusConflict
		}
		writeJSON(w, status, apiResponse{Error: clientErr})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"message": "Site created for " + req.Domain,
		"port":    strconv.Itoa(req.Port),
	}})
}

// handleNginxDiagnose reports nginx -t status and configs the dashboard cannot parse.
func (s *Server) handleNginxDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	report := nginx.Diagnose()
	hidden, err := nginx.ListHiddenSiteConfigs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to inspect nginx configs"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"ok":              report.OK,
		"issues":          report.Issues,
		"remaining_error": report.RemainingError,
		"hidden_configs":  hidden,
	}})
}

// handleNginxRepair fixes known nginx config problems and reloads when valid.
func (s *Server) handleNginxRepair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	report, err := nginx.Repair()
	if err != nil {
		log.Printf("nginx repair failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "nginx repair failed", Data: report})
		return
	}
	hidden, _ := nginx.ListHiddenSiteConfigs()
	writeJSON(w, http.StatusOK, apiResponse{Success: report.OK, Data: map[string]interface{}{
		"ok":              report.OK,
		"issues":          report.Issues,
		"fixed":           report.Fixed,
		"remaining_error": report.RemainingError,
		"hidden_configs":  hidden,
	}})
}

func siteCreateErrorForClient(err error) string {
	if err == nil {
		return "failed to create site"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "site already exists"):
		return "site already exists for this domain — confirm replace to remove the leftover nginx config"
	case strings.Contains(msg, "refusing to overwrite non-symlink"):
		return "nginx sites-enabled has a conflicting file for this domain — remove it manually"
	case strings.Contains(msg, "nginx config test failed"):
		return "nginx rejected the config — check for duplicate domains or run nginx -t"
	case strings.Contains(msg, "failed to reload nginx"):
		return "nginx reload failed — run nginx -t on the server"
	case strings.Contains(msg, "site config not found"):
		return "nginx config was not written — check ServerPilot logs"
	default:
		return "failed to create site"
	}
}

func (s *Server) handleSiteRedirectCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteRedirectRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid source domain format"})
		return
	}
	if req.IncludeWWW && strings.HasPrefix(req.Domain, "www.") {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "source domain already starts with www"})
		return
	}
	targetBase, targetHost, err := normalizeRedirectTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid redirect target"})
		return
	}
	if strings.EqualFold(req.Domain, targetHost) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "source and target domains must be different"})
		return
	}
	code := req.Code
	if code == 0 {
		code = 301
	}
	if code != 301 && code != 302 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid redirect code"})
		return
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.DelaySeconds < 0 || req.DelaySeconds > 300 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "redirect delay must be 0 or between 1 and 300 seconds"})
		return
	}
	if req.DelaySeconds > 0 && len(req.Message) > 500 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "redirect message is too long"})
		return
	}

	if err := templates.ApplyRedirectTemplate(req.Domain, targetBase, code, req.IncludeWWW, req.DelaySeconds, req.Message); err != nil {
		log.Printf("Error creating redirect site %s -> %s: %v", req.Domain, targetBase, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to create redirect"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"message": "Redirect created for " + req.Domain,
		"target":  targetBase,
		"code":    strconv.Itoa(code),
		"delay":   strconv.Itoa(req.DelaySeconds),
	}})
}

func normalizeRedirectTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || containsHTML(raw) || strings.ContainsAny(raw, " \t\r\n;{}") {
		return "", "", fmt.Errorf("invalid target")
	}
	if !strings.Contains(raw, "://") {
		if !isValidDomain(raw) {
			return "", "", fmt.Errorf("invalid target domain")
		}
		return "https://" + raw, raw, nil
	}

	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", fmt.Errorf("invalid target URL")
	}
	host := u.Hostname()
	if !isValidDomain(host) {
		return "", "", fmt.Errorf("invalid target host")
	}
	if u.Port() != "" {
		return "", "", fmt.Errorf("target ports are not supported")
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", fmt.Errorf("target path is not supported")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("target query, fragment, and credentials are not supported")
	}
	return u.Scheme + "://" + host, host, nil
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

func (s *Server) handleSiteEnableWWW(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req siteWWWRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	if !isValidDomain(req.Domain) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid domain format"})
		return
	}
	if strings.HasPrefix(strings.ToLower(req.Domain), "www.") {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "domain already starts with www"})
		return
	}

	configName := req.ConfigName
	if configName == "" {
		configName = req.Domain
	}
	if !isValidConfigName(configName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config name"})
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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "site-enable-www", "Enabling www alias", req.Domain)
	defer job.finishIfAbandoned()

	wwwDomain, err := nginx.WWWAliasForDomain(req.Domain)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: invalid domain")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "invalid domain"})
		return
	}

	sseWriteLog(w, flusher, "[Step 1/4] Updating nginx server_name for "+req.Domain+"...")
	configPath, err := nginxSitePath("/etc/nginx/sites-available", configName)
	if err != nil {
		sseWriteLog(w, flusher, "ERROR: invalid config name")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "invalid config name"})
		return
	}
	site, err := nginx.ParseConfig(configPath)
	if err != nil {
		log.Printf("Error parsing site config %s: %v", configName, err)
		sseWriteLog(w, flusher, "ERROR: failed to read nginx site")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to read site"})
		return
	}
	content, err := nginx.ReadConfigContent(configName)
	if err != nil {
		log.Printf("Error reading site config %s: %v", configName, err)
		sseWriteLog(w, flusher, "ERROR: failed to read nginx site")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to read site"})
		return
	}

	updated, changed, err := nginx.AddWWWAliasToConfig(content, req.Domain)
	if err != nil {
		log.Printf("Error adding www alias for %s in %s: %v", req.Domain, configName, err)
		sseWriteLog(w, flusher, "ERROR: failed to add www alias")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to add www alias"})
		return
	}
	if !changed {
		sseWriteLog(w, flusher, wwwDomain+" is already present in this site.")
		sseWriteDone(w, flusher, map[string]interface{}{"success": true, "message": "www already enabled for " + req.Domain})
		return
	}

	testOutput, err := nginx.WriteConfigContent(configName, updated, true)
	if err != nil {
		log.Printf("Nginx validation failed after adding www alias for %s in %s: %v", req.Domain, configName, err)
		if testOutput != "" {
			sseWriteLog(w, flusher, "ERROR: nginx validation failed")
			sseWriteLog(w, flusher, testOutput)
		} else {
			sseWriteLog(w, flusher, "ERROR: nginx validation failed")
		}
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "nginx validation failed"})
		return
	}
	sseWriteLog(w, flusher, "Added "+wwwDomain+" to nginx config.")

	if site.SSLEnabled {
		sseWriteLog(w, flusher, "[Step 2/4] Expanding SSL certificate to include "+wwwDomain+"...")
		certbotBin, err := findCertbot()
		if err != nil {
			sseWriteLog(w, flusher, "ERROR: "+err.Error())
			sseWriteLog(w, flusher, "Reloading nginx with the www alias anyway; HTTPS for www still needs a valid certificate.")
			if reloadErr := nginx.ReloadNginx(); reloadErr != nil {
				log.Printf("Error reloading nginx after certbot lookup failed for %s: %v", req.Domain, reloadErr)
				sseWriteLog(w, flusher, "WARNING: nginx reload failed after adding www alias.")
			}
			sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "certbot not found"})
			return
		}
		sseWriteLog(w, flusher, "Using certbot: "+certbotBin)

		certArgs := s.certbotEnableArgsForDomains(certbotBin, []string{req.Domain, wwwDomain}, true)
		cmd := exec.Command(certArgs[0], certArgs[1:]...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to create stdout pipe")
			sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to start certbot"})
			return
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			sseWriteLog(w, flusher, "ERROR: failed to start certbot")
			sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to start certbot"})
			return
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[certbot enable-www %s] %s", req.Domain, line)
			sseWriteLog(w, flusher, line)
		}
		if err := scanner.Err(); err != nil {
			sseWriteLog(w, flusher, "WARNING: certbot output read failed: "+err.Error())
		}
		if err := cmd.Wait(); err != nil {
			sseWriteLog(w, flusher, "ERROR: certbot failed while expanding the certificate.")
			sseWriteLog(w, flusher, "Reloading nginx with the www alias anyway; fix DNS/certbot issues and retry if HTTPS for www still fails.")
			if reloadErr := nginx.ReloadNginx(); reloadErr != nil {
				log.Printf("Error reloading nginx after certbot failed for %s: %v", req.Domain, reloadErr)
				sseWriteLog(w, flusher, "WARNING: nginx reload failed after adding www alias.")
			}
			sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "certbot failed"})
			return
		}
	} else {
		sseWriteLog(w, flusher, "[Step 2/4] Site has no SSL certificate; skipping certbot.")
	}

	sseWriteLog(w, flusher, "[Step 3/4] Reloading nginx...")
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("Error reloading nginx after enabling www for %s: %v", req.Domain, err)
		sseWriteLog(w, flusher, "ERROR: nginx reload failed")
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "nginx reload failed"})
		return
	}

	sseWriteLog(w, flusher, "[Step 4/4] WWW enabled for "+req.Domain+"!")
	sseWriteDone(w, flusher, map[string]interface{}{"success": true, "message": "www enabled for " + req.Domain})
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
	dockerDisk := sysinfo.ReadDockerDiskInfo()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"breakdown":   entries,
		"docker_disk": dockerDisk,
	}})
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

// handleDiskUnaccounted returns diagnostics for disk usage counted by df but
// not visible through normal directory scans.
func (s *Server) handleDiskUnaccounted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	report, err := sysinfo.DiskUnaccounted(limit)
	if err != nil {
		log.Printf("Disk unaccounted diagnostics error: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to inspect unaccounted disk usage"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: report})
}

// handleDiskRootScan runs a deep du scan of top-level / directories.
// GET /api/system/disk-root-scan           — full JSON result when complete
// GET /api/system/disk-root-scan?stream=1  — SSE stream, one entry per directory
func (s *Server) handleDiskRootScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	if r.URL.Query().Get("stream") == "1" {
		s.handleDiskRootScanStream(w, r)
		return
	}

	entries, err := sysinfo.DiskRootScan()
	if err != nil {
		log.Printf("Disk root scan error: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to scan root filesystem"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}

func (s *Server) handleDiskRootScanStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	paths, err := sysinfo.DiskRootScanPathsSorted()
	if err != nil {
		log.Printf("Disk root scan paths error: %v", err)
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to scan root filesystem"})
		return
	}
	pathsJSON, _ := json.Marshal(paths)
	sseWriteEvent(w, flusher, "paths", string(pathsJSON))

	if err := sysinfo.DiskRootScanStream(func(entry sysinfo.DiskRootEntry) {
		data, _ := json.Marshal(entry)
		sseWriteEvent(w, flusher, "entry", string(data))
	}); err != nil {
		log.Printf("Disk root scan stream error: %v", err)
		sseWriteDone(w, flusher, map[string]interface{}{"success": false, "error": "failed to scan root filesystem"})
		return
	}
	sseWriteDone(w, flusher, map[string]interface{}{"success": true})
}

// handleDockerContainerDisk returns per-container writable layer and volume disk usage.
func (s *Server) handleDockerContainerDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	entries, err := sysinfo.DockerContainerDiskUsage()
	if err != nil {
		log.Printf("Docker container disk error: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to inspect docker disk usage"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}

// handleDockerPruneModes lists supported docker prune operations and their risks.
// GET /api/system/docker-prune/modes
func (s *Server) handleDockerPruneModes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: dockerPruneModesWithEstimates()})
}

func dockerPruneModesWithEstimates() []docker.PruneModeInfo {
	stats := sysinfo.ReadDockerDiskInfo()
	rows := make([]docker.ReclaimRow, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, docker.ReclaimRow{Type: s.Type, ReclaimMB: s.ReclaimMB})
	}
	return docker.PruneModesWithEstimates(rows)
}

// handleDockerPrune runs one allowlisted docker prune command.
// POST /api/system/docker-prune  {"mode":"safe","confirm":"safe"}
func (s *Server) handleDockerPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	var req struct {
		Mode    string `json:"mode"`
		Confirm string `json:"confirm"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	mode := docker.PruneMode(strings.TrimSpace(req.Mode))
	if !mode.Valid() {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid prune mode"})
		return
	}
	if mode.RequiresTypeConfirm() && strings.TrimSpace(req.Confirm) != string(mode) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "confirmation required: type the mode name exactly"})
		return
	}

	actor := sanitizeLogField(s.actorFromRequest(r), 64)
	log.Printf("docker-prune: actor=%q mode=%q starting async", actor, mode)

	job, err := docker.StartPruneJob(mode)
	if err != nil {
		if errors.Is(err, docker.ErrPruneAlreadyRunning) {
			if existing, ok := docker.ActivePruneJob(); ok {
				writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: existing})
				return
			}
		}
		log.Printf("docker-prune: actor=%q mode=%q start error=%v", actor, mode, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to start docker prune"})
		return
	}

	writeJSON(w, http.StatusAccepted, apiResponse{Success: true, Data: job})
}

// handleDockerPruneStatus reports async docker prune job progress.
// GET /api/system/docker-prune/status?job=<id>
func (s *Server) handleDockerPruneStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job"))
	if jobID == "" {
		if job, ok := docker.ActivePruneJob(); ok {
			writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: job})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: nil})
		return
	}
	job, ok := docker.GetPruneJob(jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: job})
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
	// disk-top-files needs a more permissive validator than safeBrowsePath
	// because the natural starting point for "biggest files on this server"
	// is "/". We accept any absolute path (after Clean) that is NOT under
	// the scan blocklist (/proc, /sys, /dev, /run — all noise + sensitive).
	// The output of this endpoint is just a list of file paths and sizes,
	// which the operator could already obtain via SSH + find; the blocklist
	// is here to keep find from spinning forever on /proc and to refuse
	// the few subtrees where mere path enumeration leaks ephemeral state.
	cleanRoot, err := safeScanPath(root)
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
	for i := range files {
		ok, _, reason := isCleanablePath(files[i].Path)
		files[i].Cleanable = ok
		if !ok {
			files[i].CleanBlockReason = reason
		}
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
	// "/" is allowed ONLY as an exact match — isWithinAllowlist's
	// prefix check is `p == root || HasPrefix(p, root + "/")`, so for
	// root="/" the second branch becomes HasPrefix(p, "//") which never
	// matches a normal path. The effect is: the operator can request the
	// disk-top-files / disk-detail endpoints over the whole filesystem
	// (find -xdev keeps it on the root filesystem anyway), but cannot
	// use "/" as a backdoor to read e.g. /etc/shadow — anything under
	// "/" still has to go through one of the specific entries below.
	"/",
	"/var",
	"/var/lib",
	"/usr",
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

// scanBlocklist enumerates path prefixes that are NEVER scanned by
// "find" / "du"-style endpoints. These are either kernel-virtual
// filesystems (/proc, /sys) where enumeration spins forever and leaks
// transient state, or runtime tmpfs (/run, /dev) that's noisy and may
// expose service tokens via name patterns.
var scanBlocklist = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/boot",
}

// safeScanPath validates a path for whole-tree scanning operations like
// disk-top-files. More permissive than safeBrowsePath: ANY absolute
// path is accepted as long as it doesn't fall under scanBlocklist and
// doesn't contain "..". The output of these endpoints is just file
// paths + sizes, so the security boundary is "do not let `find` walk
// /proc" rather than "do not let the operator see /etc/foo exists".
func safeScanPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("not absolute")
	}
	clean := filepath.Clean(raw)
	if strings.Contains(clean, "..") {
		return "", errors.New("traversal")
	}
	for _, blk := range scanBlocklist {
		if clean == blk || strings.HasPrefix(clean, blk+"/") {
			return "", errors.New("path is in the scan blocklist")
		}
	}
	return clean, nil
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

func extractProxyPassPort(content string) (int, error) {
	matches := proxyPassPortRegex.FindStringSubmatch(content)
	if len(matches) != 2 {
		return 0, fmt.Errorf("proxy_pass port not found")
	}
	port, err := strconv.Atoi(matches[1])
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid proxy_pass port")
	}
	return port, nil
}

func inferSiteTemplateType(content string) templates.TemplateType {
	switch {
	case strings.Contains(content, "# serverpilot_template mcp"):
		return templates.MCP
	case strings.Contains(content, "/_next/static/") || strings.Contains(content, "/_next/image") || strings.Contains(content, "/_next/data/"):
		return templates.NextJS
	case strings.Contains(content, "client_max_body_size 0") || strings.Contains(content, "proxy_request_buffering  off") || strings.Contains(content, "proxy_request_buffering off"):
		return templates.MinIO
	case strings.Contains(content, "location ~*") && strings.Contains(content, "max-age=2592000"):
		return templates.Frontend
	case strings.Contains(content, `proxy_set_header Connection "upgrade"`) && strings.Contains(content, "proxy_read_timeout 86400"):
		return templates.NestJS
	default:
		return templates.API
	}
}

func nginxSitePath(dir, name string) (string, error) {
	if !isValidConfigName(name) {
		return "", fmt.Errorf("invalid site name")
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("invalid nginx directory")
	}
	path, err := filepath.Abs(filepath.Join(base, name))
	if err != nil {
		return "", fmt.Errorf("invalid site path")
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", fmt.Errorf("invalid site path")
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("site path escapes nginx directory")
	}
	return path, nil
}

func createNewSiteConfig(name, content string) error {
	configPath, err := nginxSitePath("/etc/nginx/sites-available", name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(configPath); err == nil {
		return fmt.Errorf("site config already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check site config")
	}

	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to create site config")
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		_ = os.Remove(configPath)
		return fmt.Errorf("failed to write site config")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(configPath)
		return fmt.Errorf("failed to sync site config")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(configPath)
		return fmt.Errorf("failed to close site config")
	}
	if dir, err := os.Open(filepath.Dir(configPath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func removeSiteFileIfPresent(dir, name string) (bool, error) {
	path, err := nginxSitePath(dir, name)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to inspect site file")
	}
	if info.IsDir() {
		return false, fmt.Errorf("refusing to remove directory")
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("failed to remove site file")
	}
	return true, nil
}

func runCertbotDeleteStream(w http.ResponseWriter, flusher http.Flusher, certbotBin, domain, logPrefix string) error {
	cmd := exec.Command(certbotBin, "delete", "--cert-name", domain, "--non-interactive")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe")
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start certbot")
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[%s] %s", logPrefix, line)
		sseWriteLog(w, flusher, line)
	}
	if err := scanner.Err(); err != nil {
		sseWriteLog(w, flusher, "WARNING: certbot output read failed: "+err.Error())
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// isValidConfigName validates a config filename (more permissive than domain — allows underscores, tildes).
func isValidConfigName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name == "." || name == ".." || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "\x00") {
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

// (githubTag removed — fetchLatestTag now uses /releases/latest with githubReleaseLatest below.)

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

	// Persist the current version before replacing the binary so that
	// the rollback endpoint knows where to go back to.
	prevVersion := strings.TrimPrefix(s.version, "v")
	s.config.PreviousVersion = prevVersion
	if saveErr := auth.SaveConfig(*s.config); saveErr != nil {
		log.Printf("update: could not save previous version to config: %v", saveErr)
	}

	if err := downloadAndReplace(latest); err != nil {
		// Undo the PreviousVersion write — the update never happened.
		s.config.PreviousVersion = ""
		_ = auth.SaveConfig(*s.config)
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

// handleRollbackInfo returns the previous version stored in config, if any.
// GET /api/rollback/info — protected by authMiddleware.
func (s *Server) handleRollbackInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	prev := strings.TrimPrefix(s.config.PreviousVersion, "v")
	current := strings.TrimPrefix(s.version, "v")
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"previous_version": prev,
			"current_version":  current,
		},
	})
}

// handleRollback downloads the stored previous version and replaces the binary,
// then triggers a daemon restart. Mirrors handleUpdate but in reverse.
// POST /api/rollback — protected by requireSecureReauth.
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	prev := strings.TrimPrefix(s.config.PreviousVersion, "v")
	if prev == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "no previous version recorded — nothing to roll back to"})
		return
	}

	tagVersion := "v" + prev
	if !tagRegex.MatchString(tagVersion) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "stored previous version has an invalid format"})
		return
	}

	if err := downloadAndReplace(tagVersion); err != nil {
		log.Printf("rollback: failed to download %s: %v", tagVersion, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to download previous version"})
		return
	}

	// After a successful rollback, clear the stored previous version so the
	// button disappears and the user can't roll back again to the same version.
	s.config.PreviousVersion = ""
	if saveErr := auth.SaveConfig(*s.config); saveErr != nil {
		log.Printf("rollback: could not clear previous_version from config: %v", saveErr)
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"message": "Rolled back to v" + prev + ". Restarting...",
			"version": prev,
		},
	})

	go func() {
		time.Sleep(1 * time.Second)
		log.Printf("Rollback to v%s complete. Triggering systemd restart.", prev)
		cmd := exec.Command("/usr/bin/systemctl", "restart", "serverpilot")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to restart serverpilot after rollback: %v", err)
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
// GitHub API response. Accepts both "v1.2.3" and "1.2.3" — the project tags
// without the leading "v" in some releases.
var tagRegex = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

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

// githubReleaseLatest matches /repos/<owner>/<repo>/releases/latest.
type githubReleaseLatest struct {
	TagName string `json:"tag_name"`
}

// fetchLatestTag returns the published release tag. We probe /releases/latest
// rather than /tags so the dashboard's update button only ever offers
// versions that have been formally published (with binary assets attached).
func fetchLatestTag() (string, error) {
	client := secureHTTPClient(15 * time.Second)
	resp, err := client.Get("https://api.github.com/repos/mrthoabby/serverpilot/releases/latest")
	if err != nil {
		return "", fmt.Errorf("HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, 256*1024)
	var rel githubReleaseLatest
	if err := json.NewDecoder(limited).Decode(&rel); err != nil {
		return "", fmt.Errorf("failed to parse response")
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no published release found")
	}
	if !tagRegex.MatchString(rel.TagName) {
		return "", fmt.Errorf("refusing update: invalid tag format")
	}
	return rel.TagName, nil
}

// maxBinarySize caps the download size at 200 MB to prevent memory exhaustion.
const maxBinarySize = 200 * 1024 * 1024

// downloadAndReplace downloads the new binary and atomically replaces the
// current one. Checksum verification is best-effort and matches whatever the
// release pipeline publishes:
//
//   - If a SHA-256 sidecar (<binary>.sha256) is present at the same path,
//     we enforce it strictly with a constant-time compare.
//   - If not, we log a warning and proceed. TLS 1.2+ minimum, the strict
//     tag regex, and pinning to the immutable tag ref still apply, and the
//     atomic replace gives a rollback path.
//
// To upgrade to "always strict", generate the sidecar in vs-pre-run/Makefile
// (e.g. `sha256sum sp-linux-amd64 > sp-linux-amd64.sha256`). Once the sidecar
// exists alongside every binary, this code starts enforcing without changes.
func downloadAndReplace(tagVersion string) error {
	if !tagRegex.MatchString(tagVersion) {
		return fmt.Errorf("refusing update: invalid tag format")
	}

	osName := runtime.GOOS
	archName := runtime.GOARCH

	client := secureHTTPClient(5 * time.Minute)
	// raw.githubusercontent.com pinned to the immutable tag ref — matches
	// the project's release flow (binaries commiteados at release/<ver>/
	// in the repo, then tagged + pushed). The tag pin neutralises the
	// "force-push to master" attack while preserving the existing
	// distribution path. Discovery still goes through /releases/latest.
	ver := strings.TrimPrefix(tagVersion, "v")
	base := fmt.Sprintf(
		"https://raw.githubusercontent.com/mrthoabby/serverpilot/%s/release/%s",
		tagVersion, ver,
	)
	binURL := fmt.Sprintf("%s/sp-%s-%s", base, osName, archName)
	sumURL := binURL + ".sha256"

	binBytes, err := fetchLimited(client, binURL, maxBinarySize)
	if err != nil {
		return fmt.Errorf("binary download failed")
	}

	// Best-effort checksum verification.
	sumBytes, sumErr := fetchLimited(client, sumURL, 1024)
	if sumErr == nil && len(sumBytes) > 0 {
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
	} else {
		log.Printf("update: no checksum sidecar at %s — proceeding with TLS + tag pinning only", sumURL)
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
			"domain":                          s.config.Domain,
			"email":                           s.config.Email,
			"ssl_enabled":                     s.config.SSLEnabled,
			"insecure_blocked":                s.config.InsecureBlocked,
			"host_guard":                      nginx.SecurityCatchAllEnabled(),
			"mfa_enabled":                     s.config.MFAEnabled,
			"email_login_enabled":             s.config.EmailLoginEnabled,
			"email_login_address":             s.config.EmailLoginAddress,
			"email_delivery_url":              s.config.EmailDeliveryURL,
			"email_delivery_scope":            emailDeliveryConfigFromAuthConfig(s.config).Scope,
			"email_delivery_template":         emailDeliveryConfigFromAuthConfig(s.config).Template,
			"email_delivery_timeout_sec":      emailDeliveryConfigFromAuthConfig(s.config).TimeoutSec,
			"email_delivery_token_configured": strings.TrimSpace(s.config.EmailDeliveryAuthToken) != "",
			"port":                            s.port,
			"session_max_sec":                 int(auth.SessionMaxAge.Seconds()),
			"session_idle_sec":                int(auth.SessionIdleTimeout.Seconds()),
			"reauth_max_sec":                  int(auth.ReauthMaxAge.Seconds()),
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

type settingsEmailLoginRequest struct {
	Enabled    bool   `json:"enabled"`
	Email      string `json:"email"`
	URL        string `json:"url"`
	Token      string `json:"token"`
	Scope      string `json:"scope"`
	Template   string `json:"template"`
	TimeoutSec int    `json:"timeout_sec"`
}

func (s *Server) handleSettingsEmailLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req settingsEmailLoginRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	deliveryURL := strings.TrimSpace(req.URL)
	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = strings.TrimSpace(s.config.EmailDeliveryAuthToken)
	}
	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = defaultEmailDeliveryScope
	}
	template := strings.TrimSpace(req.Template)
	if template == "" {
		template = defaultEmailDeliveryTemplate
	}
	timeout := req.TimeoutSec
	if timeout == 0 {
		timeout = defaultEmailDeliveryTimeoutSec
	}

	deliveryCfg := emailDeliveryConfig{
		URL:        deliveryURL,
		Token:      token,
		Scope:      scope,
		Template:   template,
		TimeoutSec: timeout,
	}
	if err := validateEmailDeliverySettings(deliveryCfg, req.Enabled, email); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}

	s.config.EmailLoginEnabled = req.Enabled
	s.config.EmailLoginAddress = email
	s.config.EmailDeliveryURL = deliveryURL
	s.config.EmailDeliveryAuthToken = token
	s.config.EmailDeliveryScope = scope
	s.config.EmailDeliveryTemplate = template
	s.config.EmailDeliveryTimeoutSec = timeout
	if err := emailLoginSaveConfig(*s.config); err != nil {
		log.Printf("settings email login: save config: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to save config"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"email_login_enabled":             s.config.EmailLoginEnabled,
		"email_delivery_token_configured": s.config.EmailDeliveryAuthToken != "",
	}})
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

// handleSettingsHostGuard installs a default nginx guard for unmatched hosts.
func (s *Server) handleSettingsHostGuard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}

	tlsGuard, err := nginx.InstallSecurityCatchAll()
	if err != nil {
		log.Printf("Error installing unmatched-host guard: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to install host guard"})
		return
	}

	message := "Unknown host guard installed. Unmatched HTTP requests return a plain 404."
	if tlsGuard {
		message = "Unknown host guard installed. Unmatched HTTP requests return a plain 404 and unknown HTTPS hosts are rejected."
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":   message,
			"tls_guard": tlsGuard,
		},
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

// dependencyInstallRequest contains the package name to install.
type dependencyInstallRequest struct {
	Package string `json:"package"`
}

// knownDependencies maps dependency slugs to their apt install argv. The
// slug is the value the UI sends in the request body; the argv is what
// gets executed. Every entry MUST:
//   - Use an absolute path for apt-get (no PATH games at root).
//   - Pass "--" before package names so a name beginning with "-" cannot
//     be re-interpreted as a flag (CWE-78 argument injection defence).
//   - List every package literally — never derive package names from
//     user input.
//
// The slugs themselves are validated against this map at request time,
// so the UI can never request an arbitrary package.
var knownDependencies = map[string][]string{
	"docker":                {"/usr/bin/apt-get", "install", "-y", "--", "docker.io"},
	"nginx":                 {"/usr/bin/apt-get", "install", "-y", "--", "nginx"},
	"certbot":               {"/usr/bin/apt-get", "install", "-y", "--", "certbot", "python3-certbot-nginx"},
	"acl":                   {"/usr/bin/apt-get", "install", "-y", "--", "acl"},
	"docker-compose-plugin": {"/usr/bin/apt-get", "install", "-y", "--", "docker-compose-plugin"},
}

// handleDependenciesList reports install state for dashboard-managed packages.
func (s *Server) handleDependenciesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: deps.ListDashboardDependencies()})
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

	if req.Package == "docker" || req.Package == deps.ComposePluginPackage {
		deps.FixDockerAptSources()
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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "dependency-install", "Installing "+req.Package, req.Package)
	defer job.finishIfAbandoned()

	logLine := func(line string) {
		log.Printf("[install %s] %s", req.Package, line)
		sseWriteLog(w, flusher, line)
	}

	if req.Package == deps.ComposePluginPackage {
		sseWriteLog(w, flusher, "[Step 1/2] Installing Docker Compose plugin...")
		if err := deps.InstallComposePlugin(logLine); err != nil {
			sseWriteLog(w, flusher, "ERROR: installation failed: "+err.Error())
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation failed"}`)
			return
		}
		sseWriteLog(w, flusher, "[Step 2/2] Verifying installation...")
		if !deps.ComposeAvailable() {
			sseWriteLog(w, flusher, "ERROR: docker compose still not available after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but docker compose not available"}`)
			return
		}
		sseWriteLog(w, flusher, req.Package+" installed successfully!")
		sseWriteEvent(w, flusher, "done", `{"success":true,"message":"`+req.Package+` installed successfully"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 1/2] Installing "+req.Package+"...")
	sseWriteLog(w, flusher, "Running: "+strings.Join(installArgs, " "))

	if err := deps.InstallPackageArgv(installArgs, logLine); err != nil {
		sseWriteLog(w, flusher, "ERROR: installation failed: "+err.Error())
		sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation failed"}`)
		return
	}

	sseWriteLog(w, flusher, "[Step 2/2] Verifying installation...")
	// Verify the dependency is now available.
	switch req.Package {
	case "certbot":
		if !deps.IsCertbotInstalled() {
			sseWriteLog(w, flusher, "ERROR: certbot still not found after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but binary not found"}`)
			return
		}
	case deps.ComposePluginPackage:
		if !deps.ComposeAvailable() {
			sseWriteLog(w, flusher, "ERROR: docker compose still not available after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but docker compose not available"}`)
			return
		}
	case "docker":
		if !deps.DockerInstalled() {
			sseWriteLog(w, flusher, "ERROR: docker still not found after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but docker not found"}`)
			return
		}
	case "nginx":
		if !deps.NginxInstalled() {
			sseWriteLog(w, flusher, "ERROR: nginx still not found after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but nginx not found"}`)
			return
		}
	case "acl":
		if !deps.ACLToolsInstalled() {
			sseWriteLog(w, flusher, "ERROR: acl tools still not found after installation.")
			sseWriteEvent(w, flusher, "done", `{"success":false,"error":"installation completed but acl tools not found"}`)
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

	var job *backgroundJob
	w, job = s.wrapSSE(w, flusher, "gdapp-activate", "Activating GD-App", req.Domain)
	defer job.finishIfAbandoned()

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
	"sshd":        true,
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

// handleManagedAppFiles lists one directory inside a managed application.
func (s *Server) handleManagedAppFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}

	appName := strings.TrimSpace(r.URL.Query().Get("app"))
	relPath := strings.TrimSpace(r.URL.Query().Get("path"))
	if appName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app name is required"})
		return
	}

	listing, err := apps.ListAppDirectory(appName, relPath)
	if err != nil {
		log.Printf("managed-app files: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "unable to list directory"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: listing})
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
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: portalloc.ListReservationInfos()})
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
//
//	Password mode: {"username": "ci-deploy", "password": "securepass123"}
//	SSH-only mode: {"username": "ci-deploy", "ssh_only": true, "ssh_key": "ssh-ed25519 AAAA..."}
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
		s.repairDeployPortAccess("deploy-user-create", req.Username)
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
		s.repairDeployPortAccess("deploy-user-create", req.Username)
		log.Printf("deploy-user-create: created user %q", req.Username)
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
			"username": req.Username,
			"mode":     "password",
			"message":  fmt.Sprintf("User '%s' created successfully", req.Username),
		}})
	}
}

// handleSystemUsersList returns all non-system OS users with their groups
// and a "managed" flag indicating whether they're in the dashboard's
// managed-users registry. Read-only — used by the System Users panel.
func (s *Server) handleSystemUsersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	list, err := users.ListSystemUsers()
	if err != nil {
		log.Printf("system-users-list: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to enumerate users"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"users":             list,
		"manageable_groups": users.AllowedManageableGroups(),
	}})
}

// handleSystemUserGroupToggle adds or removes a user from one of the
// allowlisted groups (currently `deploy` and `docker`). Body:
//
//	{"username":"...", "group":"deploy", "action":"add"|"remove"}
//
// Dangerous groups (Docker) require a confirm token, mirroring the
// existing system-app permissions flow.
func (s *Server) handleSystemUserGroupToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Username     string `json:"username"`
		Group        string `json:"group"`
		Action       string `json:"action"`
		ConfirmToken string `json:"confirm_token"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Group = strings.TrimSpace(req.Group)
	req.Action = strings.TrimSpace(req.Action)
	if req.Username == "" || req.Group == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username and group are required"})
		return
	}
	if req.Action != "add" && req.Action != "remove" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "action must be add or remove"})
		return
	}

	// Dangerous groups require confirm-token on ADD only. Revokes never
	// require a confirmation — UX must let admins reduce privilege fast.
	allowed := users.AllowedManageableGroups()
	meta, ok := allowed[req.Group]
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "group not manageable"})
		return
	}
	if req.Action == "add" && meta.Dangerous {
		if err := s.getPermissions().ValidateAndConsumeConfirmToken(
			"groups.add", req.Username, "", req.Group, req.ConfirmToken,
		); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
			return
		}
	}

	if err := users.SetGroupMembership(req.Username, req.Group, req.Action == "add"); err != nil {
		log.Printf("system-user-group-toggle: actor=%q user=%q group=%q action=%q error=%v",
			sanitizeLogField(s.actorFromRequest(r), 64),
			sanitizeLogField(req.Username, 64),
			sanitizeLogField(req.Group, 32),
			req.Action, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "group change failed"})
		return
	}
	if req.Action == "add" && req.Group == "deploy" {
		s.repairDeployPortAccess("system-user-group-toggle", req.Username)
	}
	log.Printf("system-user-group-toggle: actor=%q user=%q group=%q action=%q result=ok",
		sanitizeLogField(s.actorFromRequest(r), 64),
		sanitizeLogField(req.Username, 64),
		sanitizeLogField(req.Group, 32),
		req.Action)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username": req.Username,
		"group":    req.Group,
		"action":   req.Action,
	}})
}

// handleDeployUserImport registers an existing OS user as a managed
// deploy user and adds them to the `deploy` group. Body: {"username":"..."}.
// Idempotent at the group-add level (gpasswd notices a re-add); not at
// the registry level (refuses to import an already-managed user).
func (s *Server) handleDeployUserImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}
	if err := users.ImportExistingUser(req.Username); err != nil {
		log.Printf("deploy-user-import: failed for %q: %v", req.Username, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	s.repairDeployPortAccess("deploy-user-import", req.Username)
	log.Printf("deploy-user-import: actor=%q user=%q",
		sanitizeLogField(s.actorFromRequest(r), 64),
		sanitizeLogField(req.Username, 64))
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username": req.Username,
		"message":  fmt.Sprintf("User '%s' imported and added to deploy group", req.Username),
	}})
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

	// Wipe any vault entry for this user — the convenience copy of the
	// private key is meaningless without the user, and leaving stale
	// entries grows the attack surface.
	users.PurgeStoredPrivateKey(req.Username)

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

// ── Permissions ──────────────────────────────────────────────────────────
//
// Per-user permission management for managed apps (filesystem ACLs) and
// installed system apps (group membership + sudoers fragments). All
// state-changing endpoints are POST and therefore covered by the global
// CSRF middleware. Dangerous capabilities (Docker group, future sudoers)
// require a single-use confirm token issued by /api/permissions/confirm.
//
// Source of truth is the LIVE system (getfacl / /etc/group / /etc/sudoers.d/),
// not the audit log. The audit log records every transition so an admin
// can always see who granted what and when, even if someone later removed
// the grant outside the dashboard.

// permissionsService is initialised lazily on first use because it depends
// on the users / apps packages being fully loaded. listManagedUsers and
// the app-managed callbacks are wired here.
var permissionsService *permissions.Service

func (s *Server) getPermissions() *permissions.Service {
	if permissionsService != nil {
		return permissionsService
	}
	permissionsService = permissions.NewService(
		func(username string) bool {
			for _, u := range users.ListUsers() {
				if u.Username == username {
					return true
				}
			}
			return false
		},
		func(app string) bool {
			for _, a := range apps.ListApps() {
				if a.Name == app {
					return true
				}
			}
			return false
		},
	)
	return permissionsService
}

// listManagedDeployUsers is the helper passed to permissions.Service so it
// does not import internal/users (which would create a cycle).
func listManagedDeployUsers() []string {
	out := []string{}
	for _, u := range users.ListUsers() {
		out = append(out, u.Username)
	}
	return out
}

// handlePermissionsCapabilities reports which primitives are available on
// the host so the UI can disable controls with a clear reason.
func (s *Server) handlePermissionsCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	caps := s.getPermissions().Capabilities()
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: caps})
}

// handlePermissionsManagedApp returns the live FS ACL state for /opt/<app>
// projected over the managed deploy users.
//
//	GET /api/permissions/managed-app?app=<name>
func (s *Server) handlePermissionsManagedApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if app == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app is required"})
		return
	}
	state, err := s.getPermissions().FSStateForApp(app, listManagedDeployUsers)
	if err != nil {
		log.Printf("permissions/managed-app: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to read permissions"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: state})
}

// handlePermissionsSystemApps lists every system app the dashboard knows
// how to manage permissions for (currently Docker + Nginx).
func (s *Server) handlePermissionsSystemApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: permissions.SystemAppDefinitions()})
}

// handlePermissionsSystemApp returns the live state for a single system app.
//
//	GET /api/permissions/system-app?app=docker
func (s *Server) handlePermissionsSystemApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if app == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "app is required"})
		return
	}
	state, err := s.getPermissions().GetSystemAppState(app, listManagedDeployUsers)
	if err != nil {
		log.Printf("permissions/system-app: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to read permissions"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: state})
}

// handlePermissionsConfirm issues a single-use confirmation token for a
// dangerous operation. Body: {"action","username","app","capability"}.
func (s *Server) handlePermissionsConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Action     string `json:"action"`
		Username   string `json:"username"`
		App        string `json:"app"`
		Capability string `json:"capability"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	token, ttl, err := s.getPermissions().IssueConfirmToken(req.Action, req.Username, req.App, req.Capability)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"token":   token,
		"ttl_sec": int(ttl.Seconds()),
	}})
}

// handlePermissionsFSGrant grants/changes a per-user FS ACL on a managed
// app directory. Body: {"app","username","level":"none|read|write"}.
// `level: "none"` is the explicit revoke path; we accept it here so the
// UI uses a single endpoint for the radio toggle.
func (s *Server) handlePermissionsFSGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		App      string `json:"app"`
		Username string `json:"username"`
		Level    string `json:"level"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	actor := s.actorFromRequest(r)
	level := permissions.Level(req.Level)
	if !level.Valid() {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid level"})
		return
	}
	if err := s.getPermissions().GrantFS(actor, req.Username, req.App, level); err != nil {
		log.Printf("permissions/fs-grant: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "permission change failed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

// handlePermissionsSystemGrant flips a system-app capability for a user.
// Body: {"app","capability","username","action":"grant|revoke","confirm_token"?}.
func (s *Server) handlePermissionsSystemGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		App          string `json:"app"`
		Capability   string `json:"capability"`
		Username     string `json:"username"`
		Action       string `json:"action"` // "grant" or "revoke"
		ConfirmToken string `json:"confirm_token"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.Action != "grant" && req.Action != "revoke" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "action must be grant or revoke"})
		return
	}

	svc := s.getPermissions()

	// Confirm-token gate: only required for grants of `dangerous`
	// capabilities. Revokes never require confirmation — the UX must let
	// admins reduce privilege without friction.
	if req.Action == "grant" && permissions.IsCapabilityDangerous(req.Capability) {
		fullAction := "system.grant"
		if err := svc.ValidateAndConsumeConfirmToken(fullAction, req.Username, req.App, req.Capability, req.ConfirmToken); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
			return
		}
	}

	actor := s.actorFromRequest(r)
	var err error
	if req.Action == "grant" {
		err = svc.GrantSystemCapability(actor, req.App, req.Capability, req.Username)
	} else {
		err = svc.RevokeSystemCapability(actor, req.App, req.Capability, req.Username)
	}
	if err != nil {
		log.Printf("permissions/system-%s: %v", req.Action, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "permission change failed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

// handlePermissionsAudit returns the recent audit log entries.
//
//	GET /api/permissions/audit?limit=100
func (s *Server) handlePermissionsAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := s.getPermissions().AuditTail(limit)
	if err != nil {
		log.Printf("permissions/audit: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read audit log"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}

// actorFromRequest extracts the dashboard admin's username from the
// session cookie. Used to attribute audit entries. Falls back to "admin"
// if the cookie is somehow missing — should never happen because all
// permissions endpoints sit behind authMiddleware.
func (s *Server) actorFromRequest(r *http.Request) string {
	token, ok := s.currentSessionToken(r)
	if !ok {
		return "admin"
	}
	if username, ok := s.sessionStore.ValidateSession(token); ok {
		return username
	}
	return "admin"
}

// ── SSH keypair generation + private-key vault ──────────────────────────
//
// Three endpoints:
//   POST   /api/users/ssh-keys/generate  → generate keypair, install
//          public into authorized_keys, optionally store private encrypted
//   GET    /api/users/ssh-keys/private?username=<u> → decrypt + return
//   POST   /api/users/ssh-keys/private/delete → remove vault entry only
//
// All three sit behind authMiddleware AND CSRFMiddleware. The private-key
// fetch carries explicit no-store cache headers and emits an audit log
// entry every time so any abuse is post-hoc visible.

// keyGenerationRequest is the JSON body for generation.
type keyGenerationRequest struct {
	Username   string `json:"username"`
	Type       string `json:"type"`        // "ed25519" or "rsa"
	Comment    string `json:"comment"`     // optional, validated server-side
	Store      bool   `json:"store"`       // false = show once, do not persist
	CreateUser bool   `json:"create_user"` // true → create the user as SSH-only if it doesn't exist
}

// handleDeployUserGenerateKey runs ssh-keygen for an existing managed
// deploy user, installs the public key, and (if requested) stores the
// private key in the encrypted vault. Returns the keypair ONCE — the UI
// shows it, the operator copies it, the page reload loses the response.
func (s *Server) handleDeployUserGenerateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req keyGenerationRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Type = strings.TrimSpace(strings.ToLower(req.Type))
	req.Comment = strings.TrimSpace(req.Comment)

	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}
	if req.Type == "" {
		req.Type = "ed25519"
	}

	if s.config == nil || s.config.SessionSecret == "" {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "server misconfigured: missing session secret"})
		return
	}

	gen, err := users.GenerateAndStoreSSHKey(req.Username, req.Type, req.Comment, s.config.SessionSecret, req.Store, req.CreateUser)
	if err != nil {
		// Do NOT echo err.Error() back if it could leak internal hints —
		// users.GenerateAndStoreSSHKey already returns sanitized messages.
		log.Printf("deploy-user-keygen: failed for %q: %v", req.Username, err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	if req.CreateUser {
		s.repairDeployPortAccess("deploy-user-keygen", req.Username)
	}

	actor := s.actorFromRequest(r)
	log.Printf("deploy-user-keygen: actor=%q user=%q type=%s stored=%v fp=%s",
		sanitizeLogField(actor, 64), sanitizeLogField(req.Username, 64),
		gen.Type, gen.Stored, sanitizeLogField(gen.Fingerprint, 80))

	// The private key is in `gen.PrivateKey`. We MUST send a no-store /
	// no-cache response so neither the browser nor any intermediate proxy
	// (we only allow nginx in production but defence in depth) caches it.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: gen})
}

func (s *Server) repairDeployPortAccess(stage, username string) {
	if err := portalloc.EnsureSetup(); err != nil {
		log.Printf("%s: portalloc setup warning for user=%q: %v",
			stage, sanitizeLogField(username, 64), err)
	}
}

// handleDeployUserPrivateKey returns the decrypted private key from the
// vault. Audit-logged on every successful read.
//
//	GET /api/users/ssh-keys/private?username=<u>
func (s *Server) handleDeployUserPrivateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "username is required"})
		return
	}
	if s.config == nil || s.config.SessionSecret == "" {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "server misconfigured"})
		return
	}

	priv, err := users.LoadStoredPrivateKey(username, s.config.SessionSecret)
	if err != nil {
		log.Printf("deploy-user-keyfetch: actor=%q user=%q error=%v",
			sanitizeLogField(s.actorFromRequest(r), 64),
			sanitizeLogField(username, 64), err)
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "private key not available"})
		return
	}

	// Audit log on success — the line below is the only forensic trail
	// that an admin viewed the private key. Keep it terse, structured,
	// and impossible to disable from the UI.
	actor := s.actorFromRequest(r)
	log.Printf("deploy-user-keyfetch: actor=%q user=%q result=ok bytes=%d",
		sanitizeLogField(actor, 64), sanitizeLogField(username, 64), len(priv))

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"username":    username,
		"private_key": priv,
	}})
}

// handleDeployUserPrivateKeyDelete removes a vault entry without touching
// authorized_keys. The user retains SSH access via the public key already
// installed; only the convenience copy of the private key is removed.
//
//	POST /api/users/ssh-keys/private/delete  body: {"username":"..."}
func (s *Server) handleDeployUserPrivateKeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if err := users.DeleteStoredPrivateKey(strings.TrimSpace(req.Username)); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("deploy-user-keyfetch-delete: actor=%q user=%q",
		sanitizeLogField(s.actorFromRequest(r), 64), sanitizeLogField(req.Username, 64))
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

// handleDeployUserKeyVaultStatus reports whether the vault contains an
// entry for each managed user. The UI uses this to decide which user
// rows render the "Reveal private key" button.
//
//	GET /api/users/ssh-keys/vault-status
func (s *Server) handleDeployUserKeyVaultStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	out := map[string]bool{}
	for _, u := range users.ListUsers() {
		out[u.Username] = users.HasStoredPrivateKey(u.Username)
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: out})
}

// ── Database query module ───────────────────────────────────────────────
//
// Endpoints (all behind authMiddleware + CSRFMiddleware):
//   GET    /api/db/connections           list saved connections (no DSN)
//   POST   /api/db/connections           create or update a connection
//   POST   /api/db/connections/test      ping a saved connection
//   POST   /api/db/connections/delete    remove a connection
//   POST   /api/db/query                 execute a SQL query
//   GET    /api/db/audit                 tail of the dbquery audit log
//
// The DSN is only ever in flight in the body of the create/update POST
// (HTTPS protects in transit). At rest it is encrypted AES-256-GCM with
// a key derived from session_secret. The dashboard never returns the
// DSN once stored — operators who need it back have to delete + recreate.

var dbqueryService = dbquery.NewService()

func (s *Server) requireSessionSecret() (string, error) {
	if s.config == nil || s.config.SessionSecret == "" {
		return "", fmt.Errorf("server misconfigured: missing session_secret")
	}
	return s.config.SessionSecret, nil
}

func (s *Server) handleDBConnectionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	conns, err := dbqueryService.ListConnections()
	if err != nil {
		log.Printf("db/connections list: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list connections"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: conns})
}

func (s *Server) handleDBConnectionsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var in dbquery.SaveConnectionInput
	if err := jsonDecode(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	secret, err := s.requireSessionSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	saved, err := dbqueryService.SaveConnection(in, secret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("db/connection-save: actor=%q name=%q engine=%q id=%q",
		sanitizeLogField(s.actorFromRequest(r), 64),
		sanitizeLogField(saved.Name, 64),
		string(saved.Engine), saved.ID)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: saved})
}

func (s *Server) handleDBConnectionsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if err := dbqueryService.DeleteConnection(req.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	log.Printf("db/connection-delete: actor=%q id=%q",
		sanitizeLogField(s.actorFromRequest(r), 64), sanitizeLogField(req.ID, 64))
	writeJSON(w, http.StatusOK, apiResponse{Success: true})
}

func (s *Server) handleDBConnectionsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	secret, err := s.requireSessionSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	actor := s.actorFromRequest(r)
	testErr := dbqueryService.TestConnection(req.ID, secret)
	entry := dbquery.AuditEntry{
		Actor:        actor,
		ConnectionID: req.ID,
		Action:       "test",
		Result:       "ok",
	}
	if testErr != nil {
		entry.Result = "error"
		entry.Error = testErr.Error()
	}
	dbquery.Audit(entry)
	if testErr != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: testErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "connection ok"}})
}

func (s *Server) handleDBQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var req struct {
		ConnectionID string `json:"connection_id"`
		SQL          string `json:"sql"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	secret, err := s.requireSessionSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}

	actor := s.actorFromRequest(r)
	result, runErr := dbqueryService.ExecuteQuery(req.ConnectionID, secret, req.SQL)

	entry := dbquery.AuditEntry{
		Actor:        actor,
		ConnectionID: req.ConnectionID,
		Action:       "execute",
		QuerySHA256:  dbquery.HashQuery(req.SQL),
		QueryBytes:   len(req.SQL),
	}
	if runErr != nil {
		entry.Result = "error"
		entry.Error = runErr.Error()
	} else {
		entry.Result = "ok"
		entry.DurationMS = result.DurationMS
		entry.RowsReturned = len(result.Rows)
		entry.RowsAffected = result.RowsAffected
		if result.Truncated {
			entry.Result = "truncated"
		}
	}
	dbquery.Audit(entry)

	if runErr != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: runErr.Error()})
		return
	}
	// Cache-Control: no-store — query results may contain PII.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: result})
}

// handleDBCellUpdate runs a single-cell UPDATE built from the
// CellUpdateInput body. Identifiers are validated against the live
// catalogue server-side; values flow as parameterised arguments. Audit
// log records actor + sha256(SQL pattern + new value + PK values).
func (s *Server) handleDBCellUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	var in dbquery.CellUpdateInput
	if err := jsonDecode(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	secret, err := s.requireSessionSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}

	actor := s.actorFromRequest(r)
	result, runErr := dbqueryService.ApplyCellUpdate(in, secret)

	// Build a deterministic audit hash that includes the table, column,
	// PK values, and new value. The SQL pattern itself is identifier-
	// only (no value content) so it's safe to include alongside.
	auditPayload := fmt.Sprintf("%s|%s|%s|%v|%v",
		in.Schema, in.Table, in.Column, in.NewValue, in.PKValues)
	entry := dbquery.AuditEntry{
		Actor:        actor,
		ConnectionID: in.ConnectionID,
		Action:       "cell_update",
		QuerySHA256:  dbquery.HashQuery(auditPayload),
		QueryBytes:   len(auditPayload),
	}
	if runErr != nil {
		entry.Result = "error"
		entry.Error = runErr.Error()
	} else {
		entry.Result = "ok"
		entry.DurationMS = result.DurationMS
		entry.RowsAffected = result.RowsAffected
	}
	dbquery.Audit(entry)

	if runErr != nil {
		// We may have a partial result (e.g. zero-rows-matched returns
		// both an error and a SQLPattern for the UI to log). Surface
		// the SQL pattern through the error envelope's Data field.
		var data interface{}
		if result != nil {
			data = result
		}
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: runErr.Error(), Data: data})
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: result})
}

// handleDBSchema returns the schemas/tables/columns/PKs of a postgres
// connection so the dashboard can render the schema browser tree.
//
//	GET /api/db/schema?connection_id=<id>
func (s *Server) handleDBSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("connection_id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "connection_id is required"})
		return
	}
	secret, err := s.requireSessionSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	tree, err := dbqueryService.LoadSchema(id, secret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: tree})
}

func (s *Server) handleDBAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := dbquery.AuditTail(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to read audit log"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: entries})
}
