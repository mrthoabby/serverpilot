package compose

import (
	"context"
	"fmt"
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
	args := append(base, subcmd...)
	ctx, _ := r.withContext()
	cmd := exec.CommandContext(ctx, dockerBin, args...)
	cmd.Dir = r.ProjectRoot
	cmd.Env = minimalComposeEnv(r.EnvFile)
	return cmd, nil
}

func (r *Runner) upArgs() ([]string, error) {
	base, err := r.baseArgs()
	if err != nil {
		return nil, err
	}
	args := append(base, "up", "-d", "--remove-orphans")
	if r.EnvFile != "" {
		args = append(args, "--env-file", r.EnvFile)
	}
	return args, nil
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

// Up starts the stack in detached mode.
func (r *Runner) Up() error {
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
	cmd.Env = minimalComposeEnv(r.EnvFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compose up failed")
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
