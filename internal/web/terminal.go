package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

const (
	terminalAccessKeyDir      = "/root/.ssh"
	terminalAccessKeyName     = "serverpilot_remote_access_ed25519"
	terminalAccessKeyComment  = "serverpilot-remote-access"
	terminalInstallCommand    = "curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh\nsudo sp setup\nsudo sp start -d"
	terminalSSHCommandExample = "ssh -i /root/.ssh/serverpilot_remote_access_ed25519 admin@<server-ip>"
	terminalSSHDefaultUser    = "admin"
	terminalSSHDefaultPort    = 22
)

var (
	diagnosticSecretPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie)=\S+`)
	diagnosticDSNPattern    = regexp.MustCompile(`://([^:\s/@]+):([^@\s]+)@`)
	terminalSSHUserPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
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

type terminalAccessKeyResponse struct {
	Exists         bool   `json:"exists"`
	PublicKey      string `json:"public_key,omitempty"`
	PublicKeyPath  string `json:"public_key_path"`
	PrivateKeyPath string `json:"private_key_path"`
	SSHCommand     string `json:"ssh_command"`
	InstallCommand string `json:"install_command"`
	Generated      bool   `json:"generated,omitempty"`
	AlreadyExisted bool   `json:"already_existed,omitempty"`
}

type terminalSSHConnectRequest struct {
	Host string
	User string
	Port int
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
	s.serveTerminalPTY(w, r, "terminal", func(ctx context.Context) (*exec.Cmd, error) {
		shell := "/bin/bash"
		if _, err := os.Stat(shell); err != nil {
			shell = "/bin/sh"
		}
		cmd := exec.CommandContext(ctx, shell, "-l")
		cmd.Env = terminalCommandEnv()
		return cmd, nil
	})
}

func (s *Server) handleTerminalSSHWS(w http.ResponseWriter, r *http.Request) {
	req, err := terminalSSHRequestFromQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid SSH connection"})
		return
	}

	privatePath, _, err := terminalAccessKeyPaths()
	if err != nil {
		log.Printf("terminal/ssh: access key path: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to prepare SSH connection"})
		return
	}
	if err := terminalAccessPrivateKeyReady(privatePath); err != nil {
		log.Printf("terminal/ssh: access key unavailable: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "SSH access key is not ready"})
		return
	}

	s.serveTerminalPTY(w, r, "terminal/ssh", func(ctx context.Context) (*exec.Cmd, error) {
		cmdPath, args := terminalSSHCommand(req, privatePath)
		cmd := exec.CommandContext(ctx, cmdPath, args...)
		cmd.Env = terminalCommandEnv()
		return cmd, nil
	})
}

func (s *Server) serveTerminalPTY(w http.ResponseWriter, r *http.Request, logPrefix string, buildCommand func(context.Context) (*exec.Cmd, error)) {
	opts := &websocket.AcceptOptions{}
	if patterns := terminalOriginPatterns(r, s.config.Domain); len(patterns) > 0 {
		opts.OriginPatterns = patterns
	}

	conn, err := websocket.Accept(w, r, opts)
	if err != nil {
		// websocket.Accept already wrote the HTTP error.
		log.Printf("%s: ws upgrade: %v", logPrefix, err)
		recordTerminalWSReject(http.StatusBadRequest, "ws_accept: "+err.Error())
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(termMaxMsgSize)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Idle timer — any keyboard input from the client resets this.
	idle := time.AfterFunc(termIdleTimeout, func() {
		log.Printf("%s: idle timeout (%s), closing session", logPrefix, termIdleTimeout)
		cancel()
	})
	defer idle.Stop()

	cmd, err := buildCommand(ctx)
	if err != nil {
		log.Printf("%s: command build: %v", logPrefix, err)
		conn.Close(websocket.StatusInternalError, "terminal unavailable")
		return
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("%s: pty start: %v", logPrefix, err)
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
						log.Printf("%s: resize: %v", logPrefix, sizeErr)
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

// handleTerminalAccessKey returns or creates the single ServerPilot-managed
// SSH key intended for outbound access from this server to newly provisioned
// hosts. It never accepts a caller-provided path or command.
func (s *Server) handleTerminalAccessKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET or POST required"})
		return
	}

	resp, err := terminalAccessKeyState(r.Context(), r.Method == http.MethodPost)
	if err != nil {
		log.Printf("terminal/access-key: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to prepare SSH access key"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: resp})
}

func terminalAccessKeyState(ctx context.Context, create bool) (terminalAccessKeyResponse, error) {
	privatePath, publicPath, err := terminalAccessKeyPaths()
	if err != nil {
		return terminalAccessKeyResponse{}, err
	}

	resp := terminalAccessKeyResponse{
		PublicKeyPath:  publicPath,
		PrivateKeyPath: privatePath,
		SSHCommand:     terminalSSHCommandExample,
		InstallCommand: terminalInstallCommand,
	}

	if publicKey, ok, err := readTerminalAccessPublicKey(publicPath); err != nil {
		return resp, err
	} else if ok {
		resp.Exists = true
		resp.PublicKey = publicKey
		resp.AlreadyExisted = create
		return resp, nil
	}

	if !create {
		return resp, nil
	}

	if info, err := os.Lstat(privatePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return resp, fmt.Errorf("refusing to use symlinked private key")
		}
		publicKey, err := deriveTerminalAccessPublicKey(ctx, privatePath, publicPath)
		if err != nil {
			return resp, err
		}
		resp.Exists = true
		resp.PublicKey = publicKey
		resp.Generated = true
		return resp, nil
	} else if !os.IsNotExist(err) {
		return resp, err
	}

	publicKey, err := generateTerminalAccessKey(ctx, privatePath, publicPath)
	if err != nil {
		return resp, err
	}
	resp.Exists = true
	resp.PublicKey = publicKey
	resp.Generated = true
	return resp, nil
}

func terminalAccessKeyPaths() (string, string, error) {
	privatePath := filepath.Join(terminalAccessKeyDir, terminalAccessKeyName)
	publicPath := privatePath + ".pub"
	for _, p := range []string{privatePath, publicPath} {
		clean := filepath.Clean(p)
		abs, err := filepath.Abs(clean)
		if err != nil {
			return "", "", err
		}
		rel, err := filepath.Rel(terminalAccessKeyDir, abs)
		if err != nil || strings.HasPrefix(rel, "..") || strings.ContainsRune(rel, filepath.Separator) {
			return "", "", fmt.Errorf("invalid SSH access key path")
		}
	}
	return privatePath, publicPath, nil
}

func readTerminalAccessPublicKey(publicPath string) (string, bool, error) {
	if info, err := os.Lstat(publicPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("refusing to use symlinked public key")
		}
	} else if !os.IsNotExist(err) {
		return "", false, err
	}
	data, err := os.ReadFile(publicPath)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	key := strings.TrimSpace(string(data))
	if !validSSHPublicKeyPrefix(key) {
		return "", false, fmt.Errorf("managed public key is invalid")
	}
	return key, true, nil
}

func generateTerminalAccessKey(ctx context.Context, privatePath, publicPath string) (string, error) {
	if err := ensureTerminalAccessKeyDir(); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen",
		"-t", "ed25519",
		"-f", privatePath,
		"-N", "",
		"-C", terminalAccessKeyComment,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("ssh-keygen failed: %s", sanitizeLogField(string(output), 500))
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(publicPath, 0o644); err != nil {
		return "", err
	}
	key, ok, err := readTerminalAccessPublicKey(publicPath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("generated public key is missing or invalid")
	}
	return key, nil
}

func deriveTerminalAccessPublicKey(ctx context.Context, privatePath, publicPath string) (string, error) {
	if err := ensureTerminalAccessKeyDir(); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-y", "-f", privatePath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}
	key := strings.TrimSpace(string(output))
	if !validSSHPublicKeyPrefix(key) {
		return "", fmt.Errorf("derived public key is invalid")
	}
	if err := os.WriteFile(publicPath, []byte(key+"\n"), 0o644); err != nil {
		return "", err
	}
	return key, nil
}

func ensureTerminalAccessKeyDir() error {
	if info, err := os.Lstat(terminalAccessKeyDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to use symlinked SSH directory")
		}
		if !info.IsDir() {
			return fmt.Errorf("SSH path is not a directory")
		}
		return os.Chmod(terminalAccessKeyDir, 0o700)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(terminalAccessKeyDir, 0o700)
}

func validSSHPublicKeyPrefix(key string) bool {
	return strings.HasPrefix(key, "ssh-ed25519 ") ||
		strings.HasPrefix(key, "ssh-rsa ") ||
		strings.HasPrefix(key, "ecdsa-sha2-")
}

func terminalCommandEnv() []string {
	return append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
	)
}

func terminalSSHRequestFromQuery(r *http.Request) (terminalSSHConnectRequest, error) {
	host, err := validateTerminalSSHHost(r.URL.Query().Get("host"))
	if err != nil {
		return terminalSSHConnectRequest{}, err
	}

	user, err := validateTerminalSSHUser(r.URL.Query().Get("user"))
	if err != nil {
		return terminalSSHConnectRequest{}, err
	}

	port := terminalSSHDefaultPort
	if raw := strings.TrimSpace(r.URL.Query().Get("port")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			return terminalSSHConnectRequest{}, fmt.Errorf("invalid SSH port")
		}
		port = parsed
	}

	return terminalSSHConnectRequest{Host: host, User: user, Port: port}, nil
}

func validateTerminalSSHUser(user string) (string, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		user = terminalSSHDefaultUser
	}
	if !terminalSSHUserPattern.MatchString(user) {
		return "", fmt.Errorf("invalid SSH user")
	}
	return user, nil
}

func validateTerminalSSHHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("invalid SSH host")
	}
	if strings.ContainsAny(host, " \t\r\n/@\\") {
		return "", fmt.Errorf("invalid SSH host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
			return "", fmt.Errorf("invalid SSH host")
		}
		return host, nil
	}

	if strings.Contains(host, ":") {
		return "", fmt.Errorf("invalid SSH host")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !validTerminalDNSLabel(label) {
			return "", fmt.Errorf("invalid SSH host")
		}
	}
	return host, nil
}

func validTerminalDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func terminalAccessPrivateKeyReady(privatePath string) error {
	info, err := os.Lstat(privatePath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use symlinked private key")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("managed private key is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return os.Chmod(privatePath, 0o600)
	}
	return nil
}

func terminalSSHCommand(req terminalSSHConnectRequest, privatePath string) (string, []string) {
	return "/usr/bin/ssh", []string{
		"-tt",
		"-i", privatePath,
		"-p", strconv.Itoa(req.Port),
		"-l", req.User,
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=/root/.ssh/known_hosts",
		"-o", "ForwardAgent=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		req.Host,
	}
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
	RequestHost              string   `json:"request_host"`
	RequestSecure            bool     `json:"request_secure"`
	ConfiguredDomain         string   `json:"configured_domain,omitempty"`
	DomainConfigured         bool     `json:"domain_configured"`
	ResolvedDomain           string   `json:"resolved_domain"`
	SSLEnabled               bool     `json:"ssl_enabled"`
	RequestHostMatchesDomain bool     `json:"request_host_matches_domain"`
	DashboardURL             string   `json:"dashboard_url,omitempty"`
	ConfigWarning            string   `json:"config_warning,omitempty"`
	SuggestedAction          string   `json:"suggested_action,omitempty"`
	HasSessionCookie         bool     `json:"has_session_cookie"`
	Authenticated            bool     `json:"authenticated"`
	RecentlyReauthenticated  bool     `json:"recently_reauthenticated"`
	ProxyOK                  bool     `json:"proxy_ok"`
	ProxyMessage             string   `json:"proxy_message,omitempty"`
	ProxyMissing             []string `json:"proxy_missing,omitempty"`
	ConfigPath               string   `json:"config_path,omitempty"`
	BlockReason              string   `json:"block_reason,omitempty"`
	CanConnect               bool     `json:"can_connect"`
	LastWSRejectStatus       int      `json:"last_ws_reject_status,omitempty"`
	LastWSRejectReason       string   `json:"last_ws_reject_reason,omitempty"`
}

// handleTerminalWSCheck returns structured preflight status for the terminal WS.
// GET /api/terminal/ws-check
func (s *Server) handleTerminalWSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "GET required"})
		return
	}

	host := terminalRequestHost(r)
	configured := s.dashboardDomain()
	sslEnabled := s.config != nil && s.config.SSLEnabled
	diag := TerminalConnectDiag{
		RequestHost:              host,
		RequestSecure:            terminalRequestIsHTTPS(r),
		ConfiguredDomain:         configured,
		DomainConfigured:         configured != "",
		SSLEnabled:               sslEnabled,
		RequestHostMatchesDomain: configured != "" && strings.EqualFold(host, configured),
		DashboardURL:             terminalDashboardURL(configured, sslEnabled),
	}
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

	if diag.DomainConfigured && diag.RequestSecure && !diag.SSLEnabled {
		diag.ConfigWarning = "ssl_not_enabled"
	} else if diag.DomainConfigured && !diag.RequestHostMatchesDomain && !terminalHostIsLocal(host) {
		diag.ConfigWarning = "host_mismatch"
	}

	switch {
	case !diag.Authenticated:
		diag.BlockReason = "session_expired"
	case !diag.RecentlyReauthenticated:
		diag.BlockReason = "reauth_required"
	case !diag.DomainConfigured && !terminalHostIsLocal(host):
		diag.BlockReason = "domain_missing"
		diag.SuggestedAction = "set_domain"
	case !diag.ProxyOK:
		diag.BlockReason = "nginx_proxy"
		diag.SuggestedAction = "fix_proxy"
	case recentReject && rejectStatus != http.StatusUnauthorized && rejectStatus != http.StatusForbidden:
		// A recent WS rejection not caused by auth — e.g. websocket.Accept failure.
		diag.BlockReason = "ws_error"
	default:
		if diag.ConfigWarning == "ssl_not_enabled" {
			diag.SuggestedAction = "enable_ssl"
		} else if diag.ConfigWarning == "host_mismatch" {
			diag.SuggestedAction = "open_configured_domain"
		}
		diag.CanConnect = true
	}

	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: diag})
}

func terminalRequestHost(r *http.Request) string {
	host := strings.TrimSpace(strings.ToLower(r.Host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func terminalRequestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func terminalHostIsLocal(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	return host == "" || host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "[::1]")
}

func terminalDashboardURL(domain string, sslEnabled bool) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}
	scheme := "http"
	if sslEnabled {
		scheme = "https"
	}
	return scheme + "://" + domain
}
