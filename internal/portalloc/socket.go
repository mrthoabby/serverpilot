package portalloc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// PortSocketPath is the Unix socket where the ServerPilot daemon accepts
// local `sp port` requests. The daemon runs as root and owns writes to
// ports.json; callers do not need deploy-group membership.
const PortSocketPath = "/run/serverpilot/port.sock"

const portSocketDir = "/run/serverpilot"

const (
	socketDialTimeout = 2 * time.Second
	socketIOTimeout   = 30 * time.Second
	maxSocketReqBytes = 4096
)

type socketRequest struct {
	Op  string `json:"op"`
	Min int    `json:"min"`
	Max int    `json:"max"`
}

type socketResponse struct {
	OK           bool          `json:"ok"`
	Port         int           `json:"port,omitempty"`
	Error        string        `json:"error,omitempty"`
	Reservations []Reservation `json:"reservations,omitempty"`
}

// StartPortSocket listens for local port-allocation requests. Only root
// (the daemon) can create the socket; it is world-writable so any local
// user running `sp port` can delegate to ServerPilot without direct
// access to /var/lib/serverpilot.
func StartPortSocket(logf func(string, ...interface{})) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.MkdirAll(portSocketDir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", portSocketDir, err)
	}
	_ = os.Remove(PortSocketPath)

	ln, err := net.Listen("unix", PortSocketPath)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", PortSocketPath, err)
	}
	if err := os.Chmod(PortSocketPath, 0o666); err != nil {
		_ = ln.Close()
		return fmt.Errorf("cannot chmod %s: %w", PortSocketPath, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if logf != nil {
					logf("portalloc: socket accept stopped: %v", err)
				}
				return
			}
			go handlePortSocketConn(conn)
		}
	}()
	return nil
}

func handlePortSocketConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(socketIOTimeout))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		writeSocketResponse(conn, socketResponse{Error: "invalid request"})
		return
	}
	if len(line) > maxSocketReqBytes {
		writeSocketResponse(conn, socketResponse{Error: "request too large"})
		return
	}

	var req socketRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeSocketResponse(conn, socketResponse{Error: "invalid json"})
		return
	}

	resp := dispatchSocketRequest(req)
	writeSocketResponse(conn, resp)
}

func dispatchSocketRequest(req socketRequest) socketResponse {
	minPort := req.Min
	maxPort := req.Max
	if minPort == 0 {
		minPort = DefaultMinPort
	}
	if maxPort == 0 {
		maxPort = DefaultMaxPort
	}

	switch req.Op {
	case "allocate":
		port, err := Allocate(minPort, maxPort)
		if err != nil {
			return socketResponse{Error: err.Error()}
		}
		return socketResponse{OK: true, Port: port}
	case "list":
		if err := SyncDetectedPorts(minPort, maxPort); err != nil {
			return socketResponse{Error: err.Error()}
		}
		return socketResponse{OK: true, Reservations: ListReservations()}
	default:
		return socketResponse{Error: "unknown op"}
	}
}

func writeSocketResponse(conn net.Conn, resp socketResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		data = []byte(`{"error":"internal error"}`)
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// AllocateCLI is the `sp port` entry point. It prefers the running daemon
// socket so callers do not need deploy-group membership; it falls back to
// direct registry access when the daemon is not running (e.g. local dev).
func AllocateCLI(minPort, maxPort int) (int, error) {
	if port, err := allocateViaSocket(minPort, maxPort); err == nil {
		return port, nil
	}
	return Allocate(minPort, maxPort)
}

// SyncAndListCLI refreshes detected ports and returns active reservations,
// preferring the daemon socket when available.
func SyncAndListCLI(minPort, maxPort int) ([]Reservation, error) {
	if reservations, err := listViaSocket(minPort, maxPort); err == nil {
		return reservations, nil
	}
	if err := SyncDetectedPorts(minPort, maxPort); err != nil {
		return nil, err
	}
	return ListReservations(), nil
}

func allocateViaSocket(minPort, maxPort int) (int, error) {
	resp, err := roundTripSocket(socketRequest{Op: "allocate", Min: minPort, Max: maxPort})
	if err != nil {
		return 0, err
	}
	if !resp.OK {
		if resp.Error != "" {
			return 0, fmt.Errorf("%s", resp.Error)
		}
		return 0, fmt.Errorf("port allocation failed")
	}
	if resp.Port < 1 {
		return 0, fmt.Errorf("port allocation failed")
	}
	return resp.Port, nil
}

func listViaSocket(minPort, maxPort int) ([]Reservation, error) {
	resp, err := roundTripSocket(socketRequest{Op: "list", Min: minPort, Max: maxPort})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return nil, fmt.Errorf("port list failed")
	}
	return resp.Reservations, nil
}

func roundTripSocket(req socketRequest) (*socketResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), socketDialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", PortSocketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(socketIOTimeout))

	data, err := json.Marshal(req)
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
	if len(line) > maxSocketReqBytes {
		return nil, fmt.Errorf("response too large")
	}

	var resp socketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
