package sites

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const composeSocketPath = "/run/serverpilot/compose.sock"

const sitesSocketDialTimeout = 5 * time.Second
const sitesSocketIOTimeout = 2 * time.Minute

// SocketRequest is the JSON payload for local site sync socket ops.
type SocketRequest struct {
	Op            string `json:"op"`
	ContainerName string `json:"container_name,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerPort string `json:"container_port,omitempty"`
}

// SocketResponse is returned by site socket operations.
type SocketResponse struct {
	OK       bool   `json:"ok"`
	HostPort int    `json:"host_port,omitempty"`
	Error    string `json:"error,omitempty"`
}

// HostPortCLI prints the registry host port for a container name.
func HostPortCLI(containerName string) error {
	if containerName == "" {
		return fmt.Errorf("--container is required")
	}
	if os.Geteuid() == 0 {
		port, ok, err := RegistryHostPortForContainer(containerName)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no site linked to container %q", containerName)
		}
		fmt.Println(port)
		return nil
	}
	resp, err := sitesViaSocket(SocketRequest{
		Op:            "sites_host_port",
		ContainerName: containerName,
	})
	if err != nil {
		return fmt.Errorf("sp sites is unavailable — ensure ServerPilot is running (sp start -d)")
	}
	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return fmt.Errorf("sites host-port failed")
	}
	if resp.HostPort <= 0 {
		return fmt.Errorf("no site linked to container %q", containerName)
	}
	fmt.Println(resp.HostPort)
	return nil
}

// SyncPortCLI repoints nginx for sites linked to a container.
func SyncPortCLI(containerName, containerID, containerPort string) error {
	if containerName == "" && containerID == "" {
		return fmt.Errorf("--container or --container-id is required")
	}
	resp, err := sitesViaSocket(SocketRequest{
		Op:            "sync_container_port",
		ContainerName: containerName,
		ContainerID:   containerID,
		ContainerPort: containerPort,
	})
	if err != nil {
		return fmt.Errorf("sp sites is unavailable — ensure ServerPilot is running (sp start -d)")
	}
	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return fmt.Errorf("sites sync-port failed")
	}
	if resp.HostPort > 0 {
		fmt.Fprintf(os.Stderr, "Synced nginx to host port %d\n", resp.HostPort)
	}
	return nil
}

func sitesViaSocket(req SocketRequest) (*SocketResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sitesSocketDialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", composeSocketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sitesSocketIOTimeout))

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	var resp SocketResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DispatchSocketRequest handles privileged site sync operations from the local socket.
func DispatchSocketRequest(req SocketRequest) SocketResponse {
	switch req.Op {
	case "sites_host_port":
		port, ok, err := RegistryHostPortForContainer(req.ContainerName)
		if err != nil {
			return SocketResponse{Error: err.Error()}
		}
		if !ok {
			return SocketResponse{Error: fmt.Sprintf("no site linked to container %q", req.ContainerName)}
		}
		return SocketResponse{OK: true, HostPort: port}
	default:
		return SocketResponse{Error: "unknown op"}
	}
}

// WriteSocketResponse encodes a site socket response.
func WriteSocketResponse(conn net.Conn, resp SocketResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		data = []byte(`{"error":"internal error"}`)
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}
