package compose

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode"
)

// ComposeSocketPath is where the ServerPilot daemon accepts local compose
// release requests. The daemon runs as root; callers do not need sudo.
const ComposeSocketPath = "/run/serverpilot/compose.sock"

const composeSocketDir = "/run/serverpilot"

const (
	composeSocketDialTimeout = 5 * time.Second
	composeSocketIOTimeout   = 10 * time.Minute
	maxComposeSocketReqBytes = 8192
)

type composeSocketRequest struct {
	Op            string `json:"op"`
	Name          string `json:"name"`
	Service       string `json:"service"`
	ComposeFile   string `json:"compose_file,omitempty"`
	ImageRef      string `json:"image_ref"`
	RegistryUser  string `json:"registry_user,omitempty"`
	RegistryToken string `json:"registry_token,omitempty"`
	Strategy      string `json:"strategy,omitempty"`
	HealthURL     string `json:"health_url,omitempty"`
	HealthTimeout string `json:"health_timeout,omitempty"`
	Drain         string `json:"drain,omitempty"`
}

type composeSocketResponse struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Log   []string `json:"log,omitempty"`
}

// StartComposeSocket listens for local compose release requests.
func StartComposeSocket(logf func(string, ...interface{})) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.MkdirAll(composeSocketDir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", composeSocketDir, err)
	}
	_ = os.Remove(ComposeSocketPath)

	ln, err := net.Listen("unix", ComposeSocketPath)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", ComposeSocketPath, err)
	}
	if err := os.Chmod(ComposeSocketPath, 0o666); err != nil {
		_ = ln.Close()
		return fmt.Errorf("cannot chmod %s: %w", ComposeSocketPath, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if logf != nil {
					logf("compose: socket accept stopped: %v", err)
				}
				return
			}
			go handleComposeSocketConn(conn)
		}
	}()
	return nil
}

func handleComposeSocketConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(composeSocketIOTimeout))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		writeComposeSocketResponse(conn, composeSocketResponse{Error: "invalid request"})
		return
	}
	if len(line) > maxComposeSocketReqBytes {
		writeComposeSocketResponse(conn, composeSocketResponse{Error: "request too large"})
		return
	}

	var req composeSocketRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeComposeSocketResponse(conn, composeSocketResponse{Error: "invalid json"})
		return
	}

	resp := dispatchComposeSocketRequest(req)
	writeComposeSocketResponse(conn, resp)
}

func dispatchComposeSocketRequest(req composeSocketRequest) composeSocketResponse {
	if req.Op != "release" {
		return composeSocketResponse{Error: "unknown op"}
	}
	if err := validateSocketImageRef(req.ImageRef); err != nil {
		return composeSocketResponse{Error: err.Error()}
	}
	if err := validateSocketSecret(req.RegistryUser); err != nil {
		return composeSocketResponse{Error: err.Error()}
	}
	if err := validateSocketSecret(req.RegistryToken); err != nil {
		return composeSocketResponse{Error: err.Error()}
	}

	var lines []string
	progress := func(msg string) {
		lines = append(lines, msg)
	}
	releaseReq := ReleaseRequest{
		Name:          req.Name,
		Service:       req.Service,
		ComposeFile:   req.ComposeFile,
		ImageRef:      req.ImageRef,
		RegistryUser:  req.RegistryUser,
		RegistryToken: req.RegistryToken,
		Strategy:      req.Strategy,
		HealthURL:     req.HealthURL,
		HealthTimeout: parseDurationOrDefault(req.HealthTimeout, defaultHealthWait),
		Drain:         parseDurationOrDefault(req.Drain, defaultDrain),
	}
	if err := ReleaseService(releaseReq, progress); err != nil {
		return composeSocketResponse{Error: err.Error(), Log: lines}
	}
	return composeSocketResponse{OK: true, Log: lines}
}

func writeComposeSocketResponse(conn net.Conn, resp composeSocketResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		data = []byte(`{"error":"internal error"}`)
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// ReleaseCLI is the `sp compose release` entry point for non-root callers.
// It delegates to the running ServerPilot daemon over a Unix socket.
func ReleaseCLI(req ReleaseRequest, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	if os.Geteuid() == 0 {
		return ReleaseService(req, progress)
	}

	resp, err := releaseViaSocket(req)
	if err != nil {
		return fmt.Errorf("sp compose release is unavailable — ensure ServerPilot is running (sp start -d)")
	}
	for _, line := range resp.Log {
		progress(line)
	}
	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return fmt.Errorf("compose release failed")
	}
	return nil
}

func releaseViaSocket(req ReleaseRequest) (*composeSocketResponse, error) {
	if req.ComposeFile == "" {
		req.ComposeFile = strings.TrimSpace(os.Getenv("COMPOSE_FILE"))
	}
	if req.ImageRef == "" {
		req.ImageRef = strings.TrimSpace(os.Getenv("IMAGE_REF"))
	}
	if req.RegistryUser == "" {
		req.RegistryUser = strings.TrimSpace(os.Getenv("REGISTRY_USER"))
	}
	if req.RegistryToken == "" {
		req.RegistryToken = strings.TrimSpace(os.Getenv("REGISTRY_TOKEN"))
	}

	socketReq := composeSocketRequest{
		Op:            "release",
		Name:          req.Name,
		Service:       req.Service,
		ComposeFile:   req.ComposeFile,
		ImageRef:      req.ImageRef,
		RegistryUser:  req.RegistryUser,
		RegistryToken: req.RegistryToken,
		Strategy:      req.Strategy,
		HealthURL:     req.HealthURL,
		HealthTimeout: req.HealthTimeout.String(),
		Drain:         req.Drain.String(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), composeSocketDialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", ComposeSocketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(composeSocketIOTimeout))

	data, err := json.Marshal(socketReq)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > maxComposeSocketReqBytes {
		return nil, fmt.Errorf("response too large")
	}

	var resp composeSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func validateSocketImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("IMAGE_REF is required")
	}
	if len(ref) > 512 {
		return fmt.Errorf("IMAGE_REF is too long")
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("IMAGE_REF contains invalid characters")
		}
	}
	return nil
}

func validateSocketSecret(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 4096 {
		return fmt.Errorf("credential value is too long")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("credential contains invalid characters")
		}
	}
	return nil
}
