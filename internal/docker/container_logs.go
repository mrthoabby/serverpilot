package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrLogsUnavailable means the container's logging driver does not expose logs
// via docker logs or a readable json-file LogPath.
var ErrLogsUnavailable = errors.New("container logs unavailable")

type dockerJSONLogRecord struct {
	Log  string `json:"log"`
	Time string `json:"time"`
}

func validateContainerIDHex(id string) error {
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

func inspectContainerLogPath(ctx context.Context, dockerBin, id string) (string, error) {
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
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}
	logPath := strings.TrimSpace(string(out))
	if logPath == "" {
		return "", nil
	}
	return logPath, nil
}

// secureDockerLogPathForRead resolves and validates a Docker json-file LogPath
// for read-only access. Unlike ClearContainerLogs (rootful /var/lib/docker only),
// this also allows rootless layouts under ~/.local/share/docker/containers/.
func secureDockerLogPathForRead(logPath string) (string, error) {
	realPath, err := filepath.EvalSymlinks(logPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve log path: %w", err)
	}
	cleaned := filepath.Clean(realPath)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("log path is not absolute")
	}
	if !strings.HasSuffix(cleaned, "-json.log") {
		return "", fmt.Errorf("unexpected log file name")
	}
	sep := string(filepath.Separator)
	if !strings.Contains(cleaned, sep+"containers"+sep) {
		return "", fmt.Errorf("log path is outside docker containers layout")
	}
	return cleaned, nil
}

func runDockerLogs(ctx context.Context, dockerBin, id string, tail int) (string, error) {
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
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return "", fmt.Errorf("failed to read logs: %s", trimmed)
		}
		return "", fmt.Errorf("failed to read logs: %w", err)
	}
	if len(output) > maxLogsBytes {
		output = output[len(output)-maxLogsBytes:]
		if idx := strings.IndexByte(string(output), '\n'); idx >= 0 && idx < len(output)-1 {
			output = output[idx+1:]
		}
	}
	return string(output), nil
}

func readJSONLogFileTail(logPath string, tail int) (string, error) {
	if tail <= 0 {
		tail = 10
	}
	if tail > maxLogsTail {
		tail = maxLogsTail
	}

	safePath, err := secureDockerLogPathForRead(logPath)
	if err != nil {
		return "", err
	}

	f, err := os.Open(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat log file: %w", err)
	}

	var reader io.Reader = f
	if info.Size() > int64(maxLogsBytes) {
		if _, err := f.Seek(-int64(maxLogsBytes), io.SeekEnd); err != nil {
			return "", fmt.Errorf("failed to seek log file: %w", err)
		}
		reader = f
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) > tail*4 {
			lines = lines[len(lines)-tail*2:]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read log file: %w", err)
	}
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	var out strings.Builder
	for i, line := range lines {
		if i > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(formatDockerJSONLogLine(line))
	}
	return out.String(), nil
}

func formatDockerJSONLogLine(line string) string {
	var rec dockerJSONLogRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return line
	}
	msg := strings.TrimSuffix(rec.Log, "\n")
	if rec.Time != "" {
		return rec.Time + " " + msg
	}
	return msg
}

func logsUnavailableFromDockerErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not support reading") ||
		strings.Contains(msg, "logging driver")
}
