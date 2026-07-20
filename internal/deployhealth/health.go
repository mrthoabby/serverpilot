package deployhealth

import (
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

// WaitHealthy blocks until the target is ready or the timeout expires.
// Order: Docker HEALTHCHECK (if defined) -> TCP on host port -> optional HTTP GET.
func WaitHealthy(opts Options) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 750 * time.Millisecond
	}
	deadline := time.Now().Add(opts.Timeout)
	hasHC := containerHasHealthcheck(opts.ContainerName)
	var lastHealthLog string
	for time.Now().Before(deadline) {
		if hasHC {
			switch inspectHealthStatus(opts.ContainerName) {
			case "healthy":
				if opts.HealthURL == "" || httpReady(opts.HostPort, opts.HealthURL) {
					return nil
				}
			case "unhealthy":
				lastHealthLog = inspectHealthLog(opts.ContainerName)
			}
		} else {
			if containerRunning(opts.ContainerName) && tcpReady(opts.HostPort) {
				if opts.HealthURL == "" || httpReady(opts.HostPort, opts.HealthURL) {
					return nil
				}
			}
		}
		time.Sleep(opts.PollInterval)
	}
	if lastHealthLog != "" {
		return fmt.Errorf("container healthcheck failed: %s", truncateHealthDetail(lastHealthLog))
	}
	return fmt.Errorf("target did not become healthy in time")
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
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return ""
	}
	out, err := exec.Command(dockerBin, "inspect", "--format", "{{if .State.Health}}{{with index .State.Health.Log (sub (len .State.Health.Log) 1)}}{{.Output}}{{end}}{{end}}", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func truncateHealthDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if len(detail) <= 240 {
		return detail
	}
	return detail[len(detail)-240:]
}

func inspectHealthStatus(name string) string {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return ""
	}
	out, err := exec.Command(dockerBin, "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{end}}", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
