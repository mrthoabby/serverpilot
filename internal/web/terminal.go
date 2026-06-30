package web

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"nhooyr.io/websocket"
)

const (
	termIdleTimeout = 10 * time.Minute
	termMaxMsgSize  = 32 << 10 // 32 KB
	termLogTimeout  = 5 * time.Second
	termLogMaxBytes = 128 << 10 // 128 KB
)

var (
	diagnosticSecretPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie)=\S+`)
	diagnosticDSNPattern    = regexp.MustCompile(`://([^:\s/@]+):([^@\s]+)@`)
)

type termResizeMsg struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type terminalServiceLogsResponse struct {
	Command string `json:"command"`
	Logs    string `json:"logs"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// handleTerminalWS upgrades the connection to a WebSocket and bridges it
// with a /bin/bash pseudo-terminal (PTY).
//
// Security model:
//   - Route is behind requireReauth: valid session + recent re-authentication required.
//   - nhooyr.io/websocket enforces same-origin by default (Origin == Host); no extra
//     OriginPatterns needed for same-origin deployments.
//   - When SSL is enabled the domain is added as an allowed origin so that the
//     nginx-proxied request (Host: example.com) still passes origin validation.
//   - Idle timeout: 10 minutes of no keyboard input kills the PTY and closes the WS.
//   - One PTY per connection; cleaned up on any disconnect or error.
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	opts := &websocket.AcceptOptions{}
	if patterns := terminalOriginPatterns(r, s.config.Domain); len(patterns) > 0 {
		opts.OriginPatterns = patterns
	}

	conn, err := websocket.Accept(w, r, opts)
	if err != nil {
		// websocket.Accept already wrote the HTTP error.
		log.Printf("terminal: ws upgrade: %v", err)
		recordTerminalWSReject(http.StatusBadRequest, "ws_accept: "+err.Error())
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(termMaxMsgSize)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Idle timer — any keyboard input from the client resets this.
	idle := time.AfterFunc(termIdleTimeout, func() {
		log.Printf("terminal: idle timeout (%s), closing session", termIdleTimeout)
		cancel()
	})
	defer idle.Stop()

	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell, "-l")
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("terminal: pty start: %v", err)
		conn.Close(websocket.StatusInternalError, "terminal unavailable")
		return
	}
	defer func() {
		ptmx.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait() //nolint:errcheck // best-effort reap of zombie
	}()

	var wg sync.WaitGroup

	// PTY output → WebSocket (binary frames).
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				if writeErr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); writeErr != nil {
					cancel()
					return
				}
			}
			if readErr != nil {
				cancel()
				return
			}
		}
	}()

	// WebSocket → PTY (binary = keyboard input; text = control messages).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			msgType, data, readErr := conn.Read(ctx)
			if readErr != nil {
				cancel()
				return
			}

			switch msgType {
			case websocket.MessageText:
				// Control message — only resize is supported.
				var msg termResizeMsg
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
					if sizeErr := pty.Setsize(ptmx, &pty.Winsize{Rows: msg.Rows, Cols: msg.Cols}); sizeErr != nil {
						log.Printf("terminal: resize: %v", sizeErr)
					}
				}

			case websocket.MessageBinary:
				// Keyboard input — reset the idle timer.
				idle.Reset(termIdleTimeout)
				if _, writeErr := ptmx.Write(data); writeErr != nil {
					cancel()
					return
				}
			}
		}
	}()

	wg.Wait()
	conn.Close(websocket.StatusNormalClosure, "")
}

// handleTerminalServiceLogs returns a bounded, redacted snapshot of the
// ServerPilot systemd journal. It intentionally does not accept arbitrary
// commands from the browser.
func (s *Server) handleTerminalServiceLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	tail, err := terminalServiceLogTail(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid tail"})
		return
	}

	cmdPath, args, display := terminalServiceLogCommand(tail)
	ctx, cancel := context.WithTimeout(r.Context(), termLogTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdPath, args...)
	output, runErr := cmd.CombinedOutput()
	logs := sanitizeDiagnosticLogText(string(output), termLogMaxBytes)
	if ctx.Err() == context.DeadlineExceeded {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: terminalServiceLogsResponse{
			Command: display,
			Logs:    logs,
			OK:      false,
			Error:   "journalctl timed out",
		}})
		return
	}
	if runErr != nil {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: terminalServiceLogsResponse{
			Command: display,
			Logs:    logs,
			OK:      false,
			Error:   "journalctl failed",
		}})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: terminalServiceLogsResponse{
		Command: display,
		Logs:    logs,
		OK:      true,
	}})
}

func terminalServiceLogTail(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("tail"))
	if raw == "" {
		return 120, nil
	}
	tail, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if tail < 1 || tail > 300 {
		return 0, strconv.ErrSyntax
	}
	return tail, nil
}

func terminalServiceLogCommand(tail int) (string, []string, string) {
	args := []string{
		"-u", "serverpilot",
		"--no-pager",
		"--output", "short-iso",
		"--lines", strconv.Itoa(tail),
	}
	return "/usr/bin/journalctl", args, "journalctl -u serverpilot --no-pager --output short-iso --lines " + strconv.Itoa(tail)
}

func sanitizeDiagnosticLogText(text string, maxBytes int) string {
	text = diagnosticSecretPattern.ReplaceAllString(text, "$1=REDACTED")
	text = diagnosticDSNPattern.ReplaceAllString(text, "://$1:REDACTED@")

	var b strings.Builder
	b.Grow(min(len(text), maxBytes))
	for _, r := range text {
		if b.Len() >= maxBytes {
			b.WriteString("\n[truncated]\n")
			break
		}
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('?')
	}
	out := strings.TrimRight(b.String(), "\n")
	if out == "" {
		return "(no logs)"
	}
	return out
}

// terminalOriginPatterns builds allowed WebSocket Origin host patterns from the
// live request Host and the configured SSL domain so nginx-proxied subdomains
// still pass nhooyr origin validation.
func terminalOriginPatterns(r *http.Request, configuredDomain string) []string {
	seen := make(map[string]bool)
	var patterns []string
	add := func(host string) {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		patterns = append(patterns, host)
	}
	add(r.Host)
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		add(host)
	}
	add(configuredDomain)
	if host, _, err := net.SplitHostPort(configuredDomain); err == nil {
		add(host)
	}
	return patterns
}

func (s *Server) dashboardDomain() string {
	if s.config == nil {
		return ""
	}
	return strings.TrimSpace(s.config.Domain)
}

func (s *Server) resolveTerminalDomain(r *http.Request) string {
	configured := s.dashboardDomain()
	var candidates []string
	seen := make(map[string]bool)
	add := func(domain string) {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" || seen[domain] || !nginx.IsValidDomainExported(domain) {
			return
		}
		seen[domain] = true
		candidates = append(candidates, domain)
	}

	add(configured)
	if r != nil {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		add(host)
	}

	for _, domain := range candidates {
		if _, err := nginx.FindDashboardVhostPath(domain, s.port); err == nil {
			return domain
		}
	}
	if configured != "" {
		return configured
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// handleTerminalProxyStatus reports whether the dashboard nginx vhost has
// WebSocket proxy headers required by /api/terminal/ws.
func (s *Server) handleTerminalProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}
	domain := s.resolveTerminalDomain(r)
	if domain == "" {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: nginx.WebSocketProxyStatus{
			OK:      false,
			Message: "Set the dashboard domain in Settings first",
		}})
		return
	}
	st, err := nginx.InspectDashboardWebSocketProxy(domain, s.port)
	if err != nil {
		log.Printf("terminal/proxy-status: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to inspect nginx config"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: st})
}

// handleTerminalFixProxy patches the dashboard nginx vhost to add WebSocket
// headers (preserving certbot SSL blocks) and reloads nginx.
func (s *Server) handleTerminalFixProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "POST required"})
		return
	}
	domain := s.resolveTerminalDomain(r)
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "dashboard domain not configured — set it in Settings"})
		return
	}
	st, err := nginx.EnsureDashboardWebSocketProxy(domain, s.port)
	if err != nil {
		log.Printf("terminal/fix-proxy: domain=%q error=%v", domain, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to fix nginx WebSocket proxy", Data: st})
		return
	}
	log.Printf("terminal/fix-proxy: domain=%q changed=%v ok=%v", domain, st.Changed, st.OK)
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: st})
}

// TerminalConnectDiag reports whether the terminal WebSocket can connect now.
type TerminalConnectDiag struct {
	RequestHost             string   `json:"request_host"`
	ResolvedDomain          string   `json:"resolved_domain"`
	HasSessionCookie        bool     `json:"has_session_cookie"`
	Authenticated           bool     `json:"authenticated"`
	RecentlyReauthenticated bool     `json:"recently_reauthenticated"`
	ProxyOK                 bool     `json:"proxy_ok"`
	ProxyMessage            string   `json:"proxy_message,omitempty"`
	ProxyMissing            []string `json:"proxy_missing,omitempty"`
	ConfigPath              string   `json:"config_path,omitempty"`
	BlockReason             string   `json:"block_reason,omitempty"`
	CanConnect              bool     `json:"can_connect"`
	LastWSRejectStatus      int      `json:"last_ws_reject_status,omitempty"`
	LastWSRejectReason      string   `json:"last_ws_reject_reason,omitempty"`
}

// handleTerminalWSCheck returns structured preflight status for the terminal WS.
// GET /api/terminal/ws-check
func (s *Server) handleTerminalWSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}

	diag := TerminalConnectDiag{RequestHost: r.Host}
	domain := s.resolveTerminalDomain(r)
	diag.ResolvedDomain = domain

	token, ok := s.currentSessionToken(r)
	diag.HasSessionCookie = ok
	if ok {
		if _, valid := s.sessionStore.ValidateSession(token); valid {
			diag.Authenticated = true
			diag.RecentlyReauthenticated = s.sessionStore.RecentlyReauthenticated(token)
		}
	}

	if domain != "" {
		if st, err := nginx.InspectDashboardWebSocketProxy(domain, s.port); err == nil {
			diag.ProxyOK = st.OK
			diag.ProxyMessage = st.Message
			diag.ProxyMissing = st.Missing
			diag.ConfigPath = st.ConfigPath
		}
	}

	// Snapshot before deciding CanConnect so non-auth accept errors can block.
	rejectStatus, rejectReason, rejectAt := snapshotTerminalWSReject()
	recentReject := rejectStatus != 0 && time.Since(rejectAt) < 5*time.Minute
	if recentReject {
		diag.LastWSRejectStatus = rejectStatus
		diag.LastWSRejectReason = rejectReason
	}

	switch {
	case !diag.Authenticated:
		diag.BlockReason = "session_expired"
	case !diag.RecentlyReauthenticated:
		diag.BlockReason = "reauth_required"
	case !diag.ProxyOK:
		diag.BlockReason = "nginx_proxy"
	case recentReject && rejectStatus != http.StatusUnauthorized && rejectStatus != http.StatusForbidden:
		// A recent WS rejection not caused by auth — e.g. websocket.Accept failure.
		diag.BlockReason = "ws_error"
	default:
		diag.CanConnect = true
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: diag})
}
