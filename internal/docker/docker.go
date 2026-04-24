package docker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// PortMapping represents a port mapping between host and container.
type PortMapping struct {
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Container represents a Docker container.
type Container struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Image     string        `json:"image"`
	Status    string        `json:"status"`
	Ports     []PortMapping `json:"ports"`
	CreatedAt time.Time     `json:"created_at"`
}

// dockerPSOutput is used for JSON parsing from docker ps.
type dockerPSOutput struct {
	ID      string `json:"ID"`
	Names   string `json:"Names"`
	Image   string `json:"Image"`
	Status  string `json:"Status"`
	Ports   string `json:"Ports"`
	Created string `json:"CreatedAt"`
}

// ListContainers returns all running Docker containers.
func ListContainers() ([]Container, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(dockerBin, "ps", "--format", "{{json .}}", "--no-trunc")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []Container
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var raw dockerPSOutput
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // skip malformed lines
		}

		createdAt, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", raw.Created)

		container := Container{
			ID:        raw.ID,
			Name:      strings.TrimPrefix(raw.Names, "/"),
			Image:     raw.Image,
			Status:    raw.Status,
			Ports:     parsePorts(raw.Ports),
			CreatedAt: createdAt,
		}
		containers = append(containers, container)
	}

	return containers, nil
}

// GetContainerDetails returns detailed information about a specific container.
func GetContainerDetails(id string) (*Container, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}

	// Validate container ID: only allow alphanumeric and colons.
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return nil, fmt.Errorf("invalid container ID format")
		}
	}

	cmd := exec.Command(dockerBin, "inspect", "--format", "{{json .}}", id)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	var inspectData struct {
		ID      string    `json:"Id"`
		Name    string    `json:"Name"`
		Created time.Time `json:"Created"`
		Config  struct {
			Image string `json:"Image"`
		} `json:"Config"`
		State struct {
			Status string `json:"Status"`
		} `json:"State"`
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
	}

	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse container details: %w", err)
	}

	var ports []PortMapping
	for containerPort, bindings := range inspectData.NetworkSettings.Ports {
		parts := strings.Split(containerPort, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		for _, binding := range bindings {
			ports = append(ports, PortMapping{
				HostPort:      binding.HostPort,
				ContainerPort: cPort,
				Protocol:      proto,
			})
		}
	}

	container := &Container{
		ID:        inspectData.ID,
		Name:      strings.TrimPrefix(inspectData.Name, "/"),
		Image:     inspectData.Config.Image,
		Status:    inspectData.State.Status,
		Ports:     ports,
		CreatedAt: inspectData.Created,
	}

	return container, nil
}

// parsePorts parses the docker ps "Ports" column into PortMapping structs.
func parsePorts(portsStr string) []PortMapping {
	var ports []PortMapping
	if portsStr == "" {
		return ports
	}

	entries := strings.Split(portsStr, ", ")
	for _, entry := range entries {
		pm := parsePortEntry(entry)
		if pm != nil {
			ports = append(ports, *pm)
		}
	}
	return ports
}

// parsePortEntry parses a single port entry like "0.0.0.0:8080->80/tcp".
func parsePortEntry(entry string) *PortMapping {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}

	protocol := "tcp"
	if idx := strings.LastIndex(entry, "/"); idx != -1 {
		protocol = entry[idx+1:]
		entry = entry[:idx]
	}

	parts := strings.Split(entry, "->")
	if len(parts) != 2 {
		return nil
	}

	hostPart := parts[0]
	containerPort := parts[1]

	// Extract just the port from host part (could be "0.0.0.0:8080" or "8080").
	hostPort := hostPart
	if idx := strings.LastIndex(hostPart, ":"); idx != -1 {
		hostPort = hostPart[idx+1:]
	}

	return &PortMapping{
		HostPort:      hostPort,
		ContainerPort: containerPort,
		Protocol:      protocol,
	}
}
