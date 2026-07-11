package compose

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

const defaultComposeTimeout = 15 * time.Minute

// Runner executes docker compose subcommands with hardened argv.
type Runner struct {
	ProjectRoot    string
	ComposeFile    string
	ComposeProject string
	ProjectEnvFile string // prod.env or .env under project root
	EnvFile        string
	OverrideFile   string
	Timeout        time.Duration
}

func (r *Runner) dockerBin() (string, error) {
	return deps.DockerPath()
}

func (r *Runner) baseArgs() ([]string, error) {
	if r.ComposeFile == "" {
		return nil, fmt.Errorf("compose file is required")
	}
	args := []string{"compose", "-f", r.ComposeFile}
	if r.OverrideFile != "" {
		args = append(args, "-f", r.OverrideFile)
	}
	if r.ComposeProject != "" {
		args = append(args, "-p", r.ComposeProject)
	}
	return args, nil
}

func (r *Runner) withContext() (context.Context, context.CancelFunc) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultComposeTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (r *Runner) command(subcmd ...string) (*exec.Cmd, error) {
	base, err := r.baseArgs()
	if err != nil {
		return nil, err
	}
	dockerBin, err := r.dockerBin()
	if err != nil {
		return nil, err
	}
	args := append(append(append([]string{}, base...), r.envFileArgs()...), subcmd...)
	ctx, _ := r.withContext()
	cmd := exec.CommandContext(ctx, dockerBin, args...)
	cmd.Dir = r.ProjectRoot
	cmd.Env = minimalComposeEnv(r.EnvFile)
	return cmd, nil
}

func (r *Runner) envFileArgs() []string {
	var args []string
	if r.ProjectEnvFile != "" {
		args = append(args, "--env-file", r.ProjectEnvFile)
	}
	if r.EnvFile != "" {
		args = append(args, "--env-file", r.EnvFile)
	}
	return args
}

func (r *Runner) upArgs() ([]string, error) {
	base, err := r.baseArgs()
	if err != nil {
		return nil, err
	}
	// --env-file is a global compose flag and must precede the "up" subcommand.
	return append(append(base, r.envFileArgs()...), "up", "-d", "--remove-orphans"), nil
}

func minimalComposeEnv(envFile string) []string {
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}
	if envFile != "" {
		env = append(env, "SP_COMPOSE_ENV_FILE="+envFile)
	}
	return env
}

// ConfigJSON returns rendered compose config as JSON bytes.
func (r *Runner) ConfigJSON() ([]byte, error) {
	cmd, err := r.command("config", "--format", "json")
	if err != nil {
		return nil, err
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("compose config failed")
	}
	return out, nil
}

// Up starts the stack in detached mode. imageRef is optional and only used when
// the compose manifest references ${IMAGE_REF} (bootstrap deploy).
func (r *Runner) Up(imageRef string) error {
	args, err := r.upArgs()
	if err != nil {
		return err
	}
	dockerBin, err := r.dockerBin()
	if err != nil {
		return err
	}
	ctx, _ := r.withContext()
	cmd := exec.CommandContext(ctx, dockerBin, args...)
	cmd.Dir = r.ProjectRoot
	cmd.Env = r.runtimeEnv(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}
	return nil
}

// Down stops and removes the stack.
func (r *Runner) Down(removeVolumes bool) error {
	args := []string{"down", "--remove-orphans"}
	if removeVolumes {
		args = append(args, "-v")
	}
	cmd, err := r.command(args...)
	if err != nil {
		return err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compose down failed")
	}
	return nil
}

func (r *Runner) runtimeEnv(imageRef string) []string {
	env := minimalComposeEnv(r.EnvFile)
	if imageRef != "" {
		env = append(env, "IMAGE_REF="+imageRef)
	}
	for _, path := range []string{r.ProjectEnvFile, r.EnvFile} {
		env = append(env, readEnvFileKV(path)...)
	}
	return env
}

func readEnvFileKV(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			out = append(out, line)
		}
	}
	return out
}

// PullService pulls the image for one compose service.
func (r *Runner) PullService(service, imageRef string) error {
	cmd, err := r.command("pull", service)
	if err != nil {
		return err
	}
	cmd.Env = r.runtimeEnv(imageRef)
	cmd.Env = r.runtimeEnv(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose pull failed: %w", err)
	}
	return nil
}

// UpServiceNoDeps recreates one service without touching dependencies.
func (r *Runner) UpServiceNoDeps(service, imageRef string) error {
	cmd, err := r.command("up", "-d", "--no-deps", "--no-build", service)
	if err != nil {
		return err
	}
	cmd.Env = r.runtimeEnv(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}
	return nil
}

func runComposeCmd(cmd *exec.Cmd) error {
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		if detail := composeErrorDetail(stderr.String()); detail != "" {
			return fmt.Errorf("%s", detail)
		}
		return err
	}
	return nil
}

func composeErrorDetail(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	lines := strings.Split(stderr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "denied") ||
			strings.Contains(lower, "required") || strings.Contains(lower, "not found") ||
			strings.Contains(lower, "invalid") || strings.Contains(lower, "failed") {
			if len(line) > 500 {
				line = line[len(line)-500:]
			}
			return line
		}
	}
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) > 500 {
		last = last[len(last)-500:]
	}
	return last
}

// PsJSON returns compose ps output as JSON lines.
func (r *Runner) PsJSON() ([]byte, error) {
	cmd, err := r.command("ps", "--format", "json")
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

// WriteOverride writes a generated override file atomically.
func WriteOverride(dir, name string, content []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return "", err
	}
	target := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, ".override-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return "", err
	}
	return target, nil
}

// RenderPortOverrideYAML builds an override that binds reserved localhost ports.
func RenderPortOverrideYAML(endpoints []Endpoint) []byte {
	var b strings.Builder
	b.WriteString("services:\n")
	byService := map[string][]Endpoint{}
	for _, ep := range endpoints {
		byService[ep.Service] = append(byService[ep.Service], ep)
	}
	serviceNames := make([]string, 0, len(byService))
	for svc := range byService {
		serviceNames = append(serviceNames, svc)
	}
	sortStrings(serviceNames)
	for _, svc := range serviceNames {
		b.WriteString("  ")
		b.WriteString(svc)
		b.WriteString(":\n    ports:\n")
		for _, ep := range byService[svc] {
			b.WriteString("      - \"127.0.0.1:${")
			b.WriteString(ep.EnvVar)
			b.WriteString("}:")
			b.WriteString(strings.TrimSuffix(ep.ContainerPort, "/tcp"))
			if ep.Protocol != "" && ep.Protocol != "tcp" {
				b.WriteString("/")
				b.WriteString(ep.Protocol)
			}
			b.WriteString("\"\n")
		}
	}
	return []byte(b.String())
}
