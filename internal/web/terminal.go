package web

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"nhooyr.io/websocket"
)

const (
	termIdleTimeout = 10 * time.Minute
	termMaxMsgSize  = 32 << 10 // 32 KB
)

type termResizeMsg struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
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
