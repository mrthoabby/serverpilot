package docker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// InspectAllPortMappings returns published and exposed-only TCP/UDP ports for a container.
func InspectAllPortMappings(id string) ([]PortMapping, error) {
	if err := validateContainerID(id); err != nil {
		return nil, err
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(dockerBin, "inspect", "--", id).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container")
	}
	var list []containerRuntimeInspect
	if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
		return nil, fmt.Errorf("failed to parse container inspect")
	}
	runtime := list[0]

	var ports []PortMapping
	seen := make(map[string]bool)
	portKeys := make([]string, 0, len(runtime.NetworkSettings.Ports))
	for k := range runtime.NetworkSettings.Ports {
		portKeys = append(portKeys, k)
	}
	sort.Strings(portKeys)
	for _, containerPort := range portKeys {
		parts := strings.Split(containerPort, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		bindings := runtime.NetworkSettings.Ports[containerPort]
		if len(bindings) == 0 {
			key := ":" + cPort + "/" + proto
			if !seen[key] {
				seen[key] = true
				ports = append(ports, PortMapping{ContainerPort: cPort, Protocol: proto})
			}
			continue
		}
		for _, b := range bindings {
			if b.HostPort == "" {
				key := ":" + cPort + "/" + proto
				if !seen[key] {
					seen[key] = true
					ports = append(ports, PortMapping{ContainerPort: cPort, Protocol: proto})
				}
				continue
			}
			key := b.HostPort + ":" + cPort + "/" + proto
			if seen[key] {
				continue
			}
			seen[key] = true
			ports = append(ports, PortMapping{
				HostPort:      b.HostPort,
				ContainerPort: cPort,
				Protocol:      proto,
			})
		}
	}
	exposedKeys := make([]string, 0, len(runtime.Config.ExposedPorts))
	for k := range runtime.Config.ExposedPorts {
		exposedKeys = append(exposedKeys, k)
	}
	sort.Strings(exposedKeys)
	for _, containerPort := range exposedKeys {
		parts := strings.Split(containerPort, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		key := ":" + cPort + "/" + proto
		if seen[key] {
			continue
		}
		seen[key] = true
		ports = append(ports, PortMapping{ContainerPort: cPort, Protocol: proto})
	}
	return ports, nil
}

// PublishAnalysis describes whether ServerPilot can safely add a host port binding.
type PublishAnalysis struct {
	CanAutoPublish bool          `json:"can_auto_publish"`
	Reasons        []string      `json:"reasons,omitempty"`
	NetworkMode    string        `json:"network_mode"`
	ExposedPorts   []PortMapping `json:"exposed_ports"`
	PublishedPorts []PortMapping `json:"published_ports"`
	ManualCommand  string        `json:"manual_command,omitempty"`
}

// AnalyzePortPublish inspects a container and reports if auto-publish is safe.
func AnalyzePortPublish(containerID string) (PublishAnalysis, error) {
	analysis := PublishAnalysis{}
	if err := validateContainerID(containerID); err != nil {
		return analysis, err
	}
	runtime, err := inspectRuntime(containerID)
	if err != nil {
		return analysis, err
	}
	analysis.NetworkMode = runtime.HostConfig.NetworkMode
	all, err := InspectAllPortMappings(containerID)
	if err != nil {
		return analysis, err
	}
	for _, p := range all {
		if p.HostPort != "" {
			analysis.PublishedPorts = append(analysis.PublishedPorts, p)
		} else if p.Protocol == "tcp" {
			analysis.ExposedPorts = append(analysis.ExposedPorts, p)
		}
	}

	mode := strings.ToLower(runtime.HostConfig.NetworkMode)
	if mode == "host" {
		analysis.Reasons = append(analysis.Reasons, "container uses host network — publish host port on the container port directly")
		return analysis, nil
	}
	if mode == "none" || strings.HasPrefix(mode, "container:") {
		analysis.Reasons = append(analysis.Reasons, "network mode does not support publishing ports from ServerPilot")
		return analysis, nil
	}
	if len(runtime.Config.Entrypoint) > 1 {
		analysis.Reasons = append(analysis.Reasons, "multi-value entrypoint cannot be safely recreated")
	}
	if !networkModeAllowsPortPublish(runtime.HostConfig.NetworkMode) {
		analysis.Reasons = append(analysis.Reasons, "network mode is not compatible with port publishing")
	}

	analysis.CanAutoPublish = len(analysis.Reasons) == 0
	if !analysis.CanAutoPublish && len(analysis.ExposedPorts) > 0 {
		p := analysis.ExposedPorts[0]
		analysis.ManualCommand = fmt.Sprintf("docker run … -p 127.0.0.1:<host_port>:%s/%s …", p.ContainerPort, p.Protocol)
	}
	return analysis, nil
}

// PublishPortRequest is the input for adding a host port binding via safe recreate.
type PublishPortRequest struct {
	ContainerID   string
	HostPort      int
	ContainerPort string
	Protocol      string
	Env           []string
}

// PublishPort recreates the container with an additional published port when safe.
func PublishPort(req PublishPortRequest) error {
	analysis, err := AnalyzePortPublish(req.ContainerID)
	if err != nil {
		return err
	}
	if !analysis.CanAutoPublish {
		return fmt.Errorf("automatic port publish is not safe for this container")
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.ContainerPort == "" {
		return fmt.Errorf("container port required")
	}
	if req.HostPort < 1 || req.HostPort > 65535 {
		return fmt.Errorf("invalid host port")
	}

	runtime, err := inspectRuntime(req.ContainerID)
	if err != nil {
		return err
	}
	name := strings.TrimPrefix(runtime.Name, "/")
	image := runtime.Image
	if image == "" {
		image = runtime.Config.Image
	}
	spec := strconv.Itoa(req.HostPort) + ":" + req.ContainerPort + "/" + req.Protocol
	args := buildRecreateRunArgs(runtime, name, image, req.Env)
	args = insertPublishPort(args, "127.0.0.1:"+spec)

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	oldName := name + "-sp-port-old-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	id := req.ContainerID

	if _, err := exec.Command(dockerBin, "stop", "--time", "10", "--", id).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop container")
	}
	if _, err := exec.Command(dockerBin, "rename", id, oldName).CombinedOutput(); err != nil {
		_ = exec.Command(dockerBin, "start", id).Run()
		return fmt.Errorf("failed to stage old container")
	}
	if _, err := exec.Command(dockerBin, args...).CombinedOutput(); err != nil {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		_ = exec.Command(dockerBin, "rename", oldName, name).Run()
		_ = exec.Command(dockerBin, "start", name).Run()
		return fmt.Errorf("failed to run replacement container")
	}
	_ = exec.Command(dockerBin, "rm", "--", oldName).Run()
	return nil
}

func insertPublishPort(args []string, publishSpec string) []string {
	out := make([]string, 0, len(args)+2)
	for i, a := range args {
		out = append(out, a)
		if a == "run" && i+1 < len(args) {
			out = append(out, "-p", publishSpec)
		}
	}
	return out
}

// PublishedTCPHostPort returns the host-side TCP port currently published for
// containerPort on the given container (by ID and/or name).
func PublishedTCPHostPort(containerID, containerName, containerPort string) (int, string, error) {
	containerPort = strings.TrimSpace(strings.Split(containerPort, "/")[0])
	if containerPort == "" {
		return 0, "", fmt.Errorf("container port is required")
	}
	if containerID != "" {
		if port, id, err := publishedTCPFromInspect(containerID, containerPort); err == nil {
			return port, id, nil
		}
	}
	containers, err := ListContainers()
	if err != nil {
		return 0, "", err
	}
	name := strings.TrimPrefix(strings.TrimSpace(containerName), "/")
	for _, c := range containers {
		if containerID != "" && c.ID != containerID {
			continue
		}
		if name != "" && c.Name != name {
			continue
		}
		for _, p := range c.Ports {
			if p.ContainerPort == containerPort && (p.Protocol == "" || p.Protocol == "tcp") && p.HostPort != "" {
				hostPort, convErr := strconv.Atoi(p.HostPort)
				if convErr != nil {
					return 0, "", fmt.Errorf("invalid published host port")
				}
				return hostPort, c.ID, nil
			}
		}
	}
	if name == "" && containerID == "" {
		return 0, "", fmt.Errorf("container not found")
	}
	return 0, "", fmt.Errorf("container has no published TCP port %s", containerPort)
}

func publishedTCPFromInspect(containerID, containerPort string) (int, string, error) {
	ports, err := InspectAllPortMappings(containerID)
	if err != nil {
		return 0, "", err
	}
	for _, p := range ports {
		if p.ContainerPort == containerPort && (p.Protocol == "" || p.Protocol == "tcp") && p.HostPort != "" {
			hostPort, convErr := strconv.Atoi(p.HostPort)
			if convErr != nil {
				return 0, "", fmt.Errorf("invalid published host port")
			}
			return hostPort, containerID, nil
		}
	}
	return 0, "", fmt.Errorf("container has no published TCP port %s", containerPort)
}
