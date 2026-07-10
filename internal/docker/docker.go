package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// dockerContainersRoot is the directory under which Docker keeps per-container
// state and json-file log files. ClearContainerLogs refuses to touch any path
// outside of this prefix as a defense in depth against future Docker layout
// changes or compromised state (CWE-22 path traversal).
const dockerContainersRoot = "/var/lib/docker/containers/"

// maxLogsBytes caps the per-call output of GetContainerLogs to keep memory and
// JSON-encoding bounded even if a noisy container produces huge single lines.
const maxLogsBytes = 256 * 1024 // 256 KiB

// maxLogsTail is the hard upper bound on the --tail flag. Callers should pass
// a small value (the dashboard requests 10); this constant defends against
// future callers asking for unbounded tails.
const maxLogsTail = 500

// PortMapping represents a port mapping between host and container.
type PortMapping struct {
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Container represents a Docker container.
type Container struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Image        string        `json:"image"`
	Status       string        `json:"status"`
	Ports        []PortMapping `json:"ports"`
	ExposedPorts []PortMapping `json:"exposed_ports,omitempty"`
	Compose      ComposeMeta   `json:"compose,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
}

// dockerPSOutput is used for JSON parsing from docker ps.
// Field tags match the explicit --format template we build in ListContainers().
type dockerPSOutput struct {
	ID      string `json:"id"`
	Names   string `json:"names"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	Ports   string `json:"ports"`
	Created string `json:"created"`
}

// ListContainers returns all running Docker containers.
// Uses an explicit --format template instead of {{json .}} to avoid
// field-name mismatches across Docker versions.
func ListContainers() ([]Container, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}

	// Build a custom JSON template with known field names so parsing never
	// silently fails due to Docker version differences.
	tmpl := `{"id":"{{.ID}}","names":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","ports":"{{.Ports}}","created":"{{.CreatedAt}}"}`
	cmd := exec.Command(dockerBin, "ps", "--format", tmpl, "--no-trunc")
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
			// Log and skip truly malformed lines, but this should not happen
			// since we control the template format above.
			fmt.Fprintf(os.Stderr, "docker ps parse warning: %v (line: %s)\n", err, line)
			continue
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

	return enrichContainers(containers)
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
	seen := make(map[string]bool)
	for containerPort, bindings := range inspectData.NetworkSettings.Ports {
		parts := strings.Split(containerPort, "/")
		cPort := parts[0]
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}
		for _, binding := range bindings {
			if binding.HostPort == "" {
				continue // exposed but not published (e.g. 9000/tcp with null bindings)
			}
			key := binding.HostPort + ":" + cPort + "/" + proto
			if seen[key] {
				continue // deduplicate IPv4/IPv6 dual-stack bindings
			}
			seen[key] = true
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

// GetContainerLogs returns the last `tail` lines of a container's combined
// stdout/stderr. The container ID must be a hex string (validated against the
// same allowlist used by GetContainerDetails — CWE-78 command-argument
// injection defense). `tail` is capped at maxLogsTail and the byte payload is
// capped at maxLogsBytes to avoid runaway memory/JSON encoding.
//
// We deliberately accept only a hex ID (not a name) because container names
// can include characters that, while accepted by Docker, would expand the
// validation surface and make it harder to argue the input is shell-safe even
// though we never use a shell. The dashboard already has the full ID returned
// by ListContainers (`--no-trunc`) so this is no UX loss.
func GetContainerLogs(id string, tail int) (string, error) {
	if tail <= 0 {
		tail = 10
	}
	if tail > maxLogsTail {
		tail = maxLogsTail
	}

	// Hex-only allowlist: identical to GetContainerDetails. Rejects any
	// shell metacharacter implicitly (none of `;&|$<>(){}[]!#\` is hex).
	if id == "" || len(id) > 128 {
		return "", fmt.Errorf("invalid container ID format")
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return "", fmt.Errorf("invalid container ID format")
		}
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return "", err
	}

	// Bound execution time so a hung docker daemon can't tie up handlers.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Arguments are passed as separate parameters — no shell, no fmt.Sprintf
	// concatenation into a command string (CWE-78).
	cmd := exec.CommandContext(
		ctx,
		dockerBin,
		"logs",
		"--tail", fmt.Sprintf("%d", tail),
		"--timestamps",
		"--",
		id,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Surface the docker error message to the caller so the handler can
		// log it server-side, but the handler is responsible for returning a
		// generic message to the client (CWE-209).
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return "", fmt.Errorf("failed to read logs: %s", trimmed)
		}
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	if len(output) > maxLogsBytes {
		// Keep the most recent bytes — the user asked for the *last* N lines.
		output = output[len(output)-maxLogsBytes:]
		// Drop a possibly truncated first line so we don't render half a row.
		if idx := strings.IndexByte(string(output), '\n'); idx >= 0 && idx < len(output)-1 {
			output = output[idx+1:]
		}
	}

	return string(output), nil
}

// RestartContainer restarts a Docker container so its main process re-reads
// the environment configured in Docker for that container. Docker does not
// allow mutating Env on an existing container; changing Env still requires a
// recreate flow. This helper is intentionally restart-only.
func RestartContainer(id string) error {
	if err := validateContainerID(id); err != nil {
		return err
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerBin, "restart", "--time", "10", "--", id)
	if out, err := cmd.CombinedOutput(); err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("failed to restart container: %s", trimmed)
		}
		return fmt.Errorf("failed to restart container: %w", err)
	}
	return nil
}

func validateContainerID(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("invalid container ID format")
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid container ID format")
		}
	}
	return nil
}

func validateContainerEnv(env []string) error {
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return fmt.Errorf("invalid environment variable")
		}
		for i, c := range key {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || (i > 0 && c >= '0' && c <= '9') {
				continue
			}
			return fmt.Errorf("invalid environment variable")
		}
	}
	return nil
}

// RecreateContainerWithEnv replaces a container with a new one using the same
// image/runtime shape and the provided environment entries. It keeps the old
// container renamed until the new docker run succeeds, then removes it. If the
// run fails, it restores and starts the original container.
func RecreateContainerWithEnv(id string, env []string) error {
	if err := validateContainerID(id); err != nil {
		return err
	}
	if err := validateContainerEnv(env); err != nil {
		return err
	}
	runtime, err := inspectRuntime(id)
	if err != nil {
		return err
	}
	name := strings.TrimPrefix(runtime.Name, "/")
	if name == "" {
		return fmt.Errorf("container has no name")
	}
	if len(runtime.Config.Entrypoint) > 1 {
		return fmt.Errorf("container entrypoint cannot be safely recreated")
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	oldName := name + "-sp-env-old-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	if out, err := exec.Command(dockerBin, "stop", "--time", "10", "--", id).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop container: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(dockerBin, "rename", id, oldName).CombinedOutput(); err != nil {
		_ = exec.Command(dockerBin, "start", id).Run()
		return fmt.Errorf("failed to stage old container: %s", strings.TrimSpace(string(out)))
	}

	image := runtime.Image
	if image == "" {
		image = runtime.Config.Image
	}
	args := buildRecreateRunArgs(runtime, name, image, env)
	if out, err := exec.Command(dockerBin, args...).CombinedOutput(); err != nil {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		_ = exec.Command(dockerBin, "rename", oldName, name).Run()
		_ = exec.Command(dockerBin, "start", name).Run()
		return fmt.Errorf("failed to run replacement container: %s", strings.TrimSpace(string(out)))
	}

	_ = exec.Command(dockerBin, "rm", "--", oldName).Run()
	return nil
}

type containerRuntimeInspect struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Name   string `json:"Name"`
	Config struct {
		Image      string            `json:"Image"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
		WorkingDir string            `json:"WorkingDir"`
		User       string            `json:"User"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode   string `json:"NetworkMode"`
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func inspectRuntime(id string) (containerRuntimeInspect, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return containerRuntimeInspect{}, err
	}
	out, err := exec.Command(dockerBin, "inspect", "--", id).Output()
	if err != nil {
		return containerRuntimeInspect{}, fmt.Errorf("failed to inspect container: %w", err)
	}
	var list []containerRuntimeInspect
	if err := json.Unmarshal(out, &list); err != nil {
		return containerRuntimeInspect{}, fmt.Errorf("failed to parse container inspect: %w", err)
	}
	if len(list) == 0 {
		return containerRuntimeInspect{}, fmt.Errorf("container not found")
	}
	return list[0], nil
}

func buildRecreateRunArgs(runtime containerRuntimeInspect, name, image string, env []string) []string {
	args := []string{"run", "-d", "--name", name}
	if runtime.Config.User != "" {
		args = append(args, "--user", runtime.Config.User)
	}
	if runtime.Config.WorkingDir != "" {
		args = append(args, "--workdir", runtime.Config.WorkingDir)
	}
	if runtime.HostConfig.RestartPolicy.Name != "" && runtime.HostConfig.RestartPolicy.Name != "no" {
		restart := runtime.HostConfig.RestartPolicy.Name
		if restart == "on-failure" && runtime.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			restart += ":" + strconv.Itoa(runtime.HostConfig.RestartPolicy.MaximumRetryCount)
		}
		args = append(args, "--restart", restart)
	}
	if runtime.HostConfig.NetworkMode != "" && runtime.HostConfig.NetworkMode != "default" && runtime.HostConfig.NetworkMode != "bridge" {
		args = append(args, "--network", runtime.HostConfig.NetworkMode)
	}
	labelKeys := make([]string, 0, len(runtime.Config.Labels))
	for k := range runtime.Config.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		v := runtime.Config.Labels[k]
		args = append(args, "--label", k+"="+v)
	}
	for _, item := range env {
		args = append(args, "-e", item)
	}
	if networkModeAllowsPortPublish(runtime.HostConfig.NetworkMode) {
		ports := make([]string, 0, len(runtime.NetworkSettings.Ports))
		for port := range runtime.NetworkSettings.Ports {
			ports = append(ports, port)
		}
		sort.Strings(ports)
		for _, port := range ports {
			bindings := runtime.NetworkSettings.Ports[port]
			if len(bindings) == 0 {
				continue
			}
			for _, b := range bindings {
				if b.HostPort == "" {
					continue
				}
				spec := b.HostPort + ":" + port
				if b.HostIP != "" && b.HostIP != "0.0.0.0" && b.HostIP != "::" {
					spec = b.HostIP + ":" + spec
				}
				args = append(args, "-p", spec)
			}
		}
	}
	for _, m := range runtime.Mounts {
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		source := m.Source
		if m.Type == "volume" && m.Name != "" {
			source = m.Name
		}
		if source == "" || m.Destination == "" {
			continue
		}
		args = append(args, "-v", source+":"+m.Destination+":"+mode)
	}
	if len(runtime.Config.Entrypoint) == 1 {
		args = append(args, "--entrypoint", runtime.Config.Entrypoint[0])
	}
	args = append(args, image)
	args = append(args, runtime.Config.Cmd...)
	return args
}

func networkModeAllowsPortPublish(mode string) bool {
	if mode == "" || mode == "default" || mode == "bridge" {
		return true
	}
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
		return false
	}
	return true
}

// ClearContainerLogs truncates the container's log file so future calls to
// `docker logs` start fresh. There is no native Docker command for this; the
// portable trick is to truncate the json-file driver's LogPath in place
// (Docker reopens it on the next write). Only json-file (and json-file-shaped)
// drivers expose a LogPath — drivers like journald/fluentd return an empty
// path and we refuse the operation rather than silently no-op.
//
// Security layers:
//
//   - Container ID is hex-only (rejects all shell metacharacters → CWE-78).
//   - The log file path is read from `docker inspect`, not constructed by
//     concatenating the id, so we honour Docker's own layout.
//   - Path is canonicalised with EvalSymlinks and then checked to live under
//     /var/lib/docker/containers/. This blocks an attacker (with the ability
//     to plant symlinks under /var/lib/docker — root-only by default) from
//     redirecting the truncate at, say, /etc/shadow.
//   - The file is opened with O_NOFOLLOW to close the symlink-swap TOCTOU
//     window between EvalSymlinks and Open.
//   - Open is O_WRONLY|O_TRUNC with mode 0 (mode is ignored when the file
//     already exists; we never create new files here).
func ClearContainerLogs(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("invalid container ID format")
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid container ID format")
		}
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ask Docker for the canonical LogPath. Separate args, no shell.
	inspect := exec.CommandContext(
		ctx,
		dockerBin,
		"inspect",
		"--format", "{{.LogPath}}",
		"--",
		id,
	)
	out, err := inspect.Output()
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}
	logPath := strings.TrimSpace(string(out))
	if logPath == "" {
		// json-file driver not in use (e.g. journald, fluentd, syslog). We
		// don't have a portable way to clear those, so be explicit instead
		// of silently appearing to succeed.
		return fmt.Errorf("container is not using a file-based log driver; cannot clear logs")
	}

	// Defense in depth: resolve symlinks before the prefix check, so a
	// symlink trick under /var/lib/docker/containers/ can't escape the jail.
	realPath, err := filepath.EvalSymlinks(logPath)
	if err != nil {
		return fmt.Errorf("failed to resolve log path: %w", err)
	}
	cleaned := filepath.Clean(realPath)
	if !strings.HasPrefix(cleaned, dockerContainersRoot) {
		return fmt.Errorf("log path is outside the docker containers directory")
	}

	// Open with O_NOFOLLOW to defeat any symlink swapped in between
	// EvalSymlinks and Open. O_TRUNC zeroes the file in place — Docker keeps
	// the same fd open for writes so subsequent log lines land at offset 0
	// and `docker logs` then returns only the new content.
	f, err := os.OpenFile(cleaned, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("failed to truncate log file: %w", err)
	}
	return f.Close()
}

// Image represents a Docker image.
type Image struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Size       string `json:"size"`
	Created    string `json:"created"`
}

// ListImages returns all local Docker images.
func ListImages() ([]Image, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}

	tmpl := `{"id":"{{.ID}}","repository":"{{.Repository}}","tag":"{{.Tag}}","size":"{{.Size}}","created":"{{.CreatedSince}}"}`
	cmd := exec.Command(dockerBin, "images", "--format", tmpl, "--no-trunc")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var images []Image
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var img Image
		if err := json.Unmarshal([]byte(line), &img); err != nil {
			fmt.Fprintf(os.Stderr, "docker images parse warning: %v (line: %s)\n", err, line)
			continue
		}
		images = append(images, img)
	}

	return images, nil
}

// RemoveImage removes a Docker image by ID. The ID must be a valid hex string.
func RemoveImage(imageID string) error {
	// Validate image ID: only allow hex chars and "sha256:" prefix.
	cleanID := strings.TrimPrefix(imageID, "sha256:")
	for _, c := range cleanID {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid image ID format")
		}
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}

	cmd := exec.Command(dockerBin, "rmi", imageID)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove image: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

// ForceRemoveImage removes a Docker image by ID with --force flag.
func ForceRemoveImage(imageID string) error {
	cleanID := strings.TrimPrefix(imageID, "sha256:")
	for _, c := range cleanID {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid image ID format")
		}
	}

	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}

	cmd := exec.Command(dockerBin, "rmi", "--force", imageID)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove image: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

// parsePorts parses the docker ps "Ports" column into PortMapping structs.
// Deduplicates entries that differ only in bind address (e.g. 0.0.0.0:9001
// and :::9001 from Docker dual-stack IPv4+IPv6 binding).
func parsePorts(portsStr string) []PortMapping {
	var ports []PortMapping
	if portsStr == "" {
		return ports
	}

	seen := make(map[string]bool)
	entries := strings.Split(portsStr, ", ")
	for _, entry := range entries {
		pm := parsePortEntry(entry)
		if pm != nil {
			key := pm.HostPort + ":" + pm.ContainerPort + "/" + pm.Protocol
			if !seen[key] {
				seen[key] = true
				ports = append(ports, *pm)
			}
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
