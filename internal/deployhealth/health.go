package deployhealth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// Options configures readiness waiting for a deployment target.
type Options struct {
	ContainerName string
	HostPort      int
	HealthURL     string
	Timeout       time.Duration
	PollInterval  time.Duration
}

type dockerHealthInspect struct {
	Status string `json:"Status"`
	Log    []struct {
		Output string `json:"Output"`
	} `json:"Log"`
}

type containerDiagnostics struct {
	StateStatus  string
	HealthStatus string
	OOMKilled    bool
	RestartCount int
	Health       dockerHealthInspect
}

// WaitHealthy blocks until the target is ready or the timeout expires.
// Order: optional host HTTP/TCP -> Docker HEALTHCHECK status -> host verify when docker healthy.
func WaitHealthy(opts Options) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Minute
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 750 * time.Millisecond
	}
	deadline := time.Now().Add(opts.Timeout)
	hasHC := containerHasHealthcheck(opts.ContainerName)
	var lastHealthLog string
	for time.Now().Before(deadline) {
		if hostEndpointReady(opts) {
			return nil
		}
		if hasHC {
			switch inspectHealthStatus(opts.ContainerName) {
			case "healthy":
				if opts.HealthURL == "" || httpReady(opts.HostPort, opts.HealthURL) {
					return nil
				}
			case "unhealthy":
				lastHealthLog = inspectHealthLog(opts.ContainerName)
			}
		} else if containerRunning(opts.ContainerName) && tcpReady(opts.HostPort) {
			if opts.HealthURL == "" || httpReady(opts.HostPort, opts.HealthURL) {
				return nil
			}
		}
		time.Sleep(opts.PollInterval)
	}
	if lastHealthLog != "" {
		return fmt.Errorf("container healthcheck failed: %s", truncateHealthDetail(lastHealthLog))
	}
	return formatWaitHealthyTimeout(opts, hasHC)
}

func hostEndpointReady(opts Options) bool {
	if opts.HostPort <= 0 || !containerRunning(opts.ContainerName) {
		return false
	}
	if opts.HealthURL != "" {
		return httpReady(opts.HostPort, opts.HealthURL)
	}
	return tcpReady(opts.HostPort)
}

func formatWaitHealthyTimeout(opts Options, hasHC bool) error {
	diag := inspectContainerDiagnostics(opts.ContainerName)
	status := strings.TrimSpace(diag.HealthStatus)
	if status == "" && hasHC {
		status = "unknown"
	}
	if status == "" && diag.StateStatus != "" {
		status = diag.StateStatus
	}
	if !hasHC && containerRunning(opts.ContainerName) {
		status = "running"
	}
	if status == "healthy" && opts.HealthURL != "" {
		return fmt.Errorf("target did not become healthy in time (docker healthy but %s not ready on host port %d)", opts.HealthURL, opts.HostPort)
	}
	logDetail := formatHealthLogs(diag.Health.Log)
	if logDetail != "" {
		msg := fmt.Sprintf("target did not become healthy in time (status=%s", status)
		if diag.RestartCount > 0 || diag.OOMKilled {
			msg += fmt.Sprintf("; restarts=%d oom=%t", diag.RestartCount, diag.OOMKilled)
		}
		msg += "): " + logDetail
		return fmt.Errorf("%s", msg)
	}
	if status != "" {
		msg := fmt.Sprintf("target did not become healthy in time (status=%s", status)
		if diag.RestartCount > 0 || diag.OOMKilled {
			msg += fmt.Sprintf("; restarts=%d oom=%t", diag.RestartCount, diag.OOMKilled)
		}
		msg += fmt.Sprintf(") — inspect: docker logs --tail 20 %s", opts.ContainerName)
		return fmt.Errorf("%s", msg)
	}
	return fmt.Errorf("target did not become healthy in time")
}

func formatHealthLogs(entries []struct {
	Output string `json:"Output"`
}) string {
	if len(entries) == 0 {
		return ""
	}
	start := len(entries) - 3
	if start < 0 {
		start = 0
	}
	var parts []string
	for _, entry := range entries[start:] {
		out := strings.TrimSpace(entry.Output)
		if out == "" {
			continue
		}
		parts = append(parts, truncateHealthDetail(out))
	}
	return strings.Join(parts, " | ")
}

func inspectContainerDiagnostics(name string) containerDiagnostics {
	diag := containerDiagnostics{}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return diag
	}
	out, err := exec.Command(dockerBin, "inspect", "--format",
		"{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{json .State.Health}}",
		name).Output()
	if err != nil {
		return diag
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 5)
	if len(parts) > 0 {
		diag.StateStatus = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		diag.HealthStatus = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		diag.OOMKilled = strings.TrimSpace(parts[2]) == "true"
	}
	if len(parts) > 3 {
		diag.RestartCount, _ = strconv.Atoi(strings.TrimSpace(parts[3]))
	}
	if len(parts) > 4 && strings.TrimSpace(parts[4]) != "" && parts[4] != "null" {
		_ = json.Unmarshal([]byte(parts[4]), &diag.Health)
	}
	return diag
}

func containerHasHealthcheck(name string) bool {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return false
	}
	out, err := exec.Command(dockerBin, "inspect", "--format", "{{if .Config.Healthcheck}}{{if .Config.Healthcheck.Test}}yes{{end}}{{end}}", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

func inspectHealthLog(name string) string {
	diag := inspectContainerDiagnostics(name)
	if len(diag.Health.Log) == 0 {
		return ""
	}
	return strings.TrimSpace(diag.Health.Log[len(diag.Health.Log)-1].Output)
}

func truncateHealthDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if len(detail) <= 240 {
		return detail
	}
	return detail[len(detail)-240:]
}

func inspectHealthStatus(name string) string {
	return inspectContainerDiagnostics(name).HealthStatus
}

func containerRunning(name string) bool {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return false
	}
	out, err := exec.Command(dockerBin, "inspect", "--format", "{{.State.Status}}", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "running"
}

func tcpReady(port int) bool {
	if port <= 0 {
		return true
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 750*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func httpReady(port int, path string) bool {
	if path == "" {
		return true
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := "http://127.0.0.1:" + strconv.Itoa(port) + path
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
