package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

const (
	defaultComposeTimeout     = 15 * time.Minute
	ensureServicesWaitTimeout = 5 * time.Minute
)

// Runner executes docker compose subcommands with hardened argv.
type Runner struct {
	ProjectRoot    string
	ComposeFile    string
	ComposeProject string
	ProjectEnvFile string // prod.env or .env under project root
	EnvFile        string
	OverrideFile   string
	ImageRef       string // optional; required when the manifest interpolates ${IMAGE_REF}
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
	cmd.Env = r.envFor("")
	return cmd, nil
}

func (r *Runner) envFor(imageRef string) []string {
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		ref = strings.TrimSpace(r.ImageRef)
	}
	return r.runtimeEnv(ref)
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
	cmd.Env = r.envFor(imageRef)
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
	return env
}

// PullService pulls the image for one compose service.
func (r *Runner) PullService(service, imageRef string) error {
	cmd, err := r.command("pull", service)
	if err != nil {
		return err
	}
	cmd.Env = r.envFor(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose pull failed: %w", err)
	}
	return nil
}

// ServiceRuntimeState reports one compose service container state.
type ServiceRuntimeState struct {
	Service string
	State   string
	Health  string
}

type composePsStateRow struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
}

func worstRuntimeState(a, b ServiceRuntimeState) ServiceRuntimeState {
	out := a
	if runtimeStateSeverity(b.State) > runtimeStateSeverity(a.State) {
		out.State = b.State
	}
	if healthSeverity(b.Health) > healthSeverity(a.Health) {
		out.Health = b.Health
	}
	return out
}

func runtimeStateSeverity(state string) int {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return 0
	case "":
		return 1
	default:
		return 2
	}
}

func healthSeverity(health string) int {
	switch strings.ToLower(strings.TrimSpace(health)) {
	case "", "healthy":
		return 0
	case "starting":
		return 1
	default:
		return 2
	}
}

// ServiceRuntimeStates returns compose ps state for the requested services.
func (r *Runner) ServiceRuntimeStates(services []string) ([]ServiceRuntimeState, error) {
	if len(services) == 0 {
		return nil, nil
	}
	args := []string{"ps", "--all", "--format", "json"}
	args = append(args, services...)
	cmd, err := r.command(args...)
	if err != nil {
		return nil, err
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("compose ps failed")
	}
	byService := map[string]ServiceRuntimeState{}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row composePsStateRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		svc := strings.TrimSpace(row.Service)
		if svc == "" {
			continue
		}
		next := ServiceRuntimeState{
			Service: svc,
			State:   strings.TrimSpace(row.State),
			Health:  strings.TrimSpace(row.Health),
		}
		if current, ok := byService[svc]; ok {
			next = worstRuntimeState(current, next)
		}
		byService[svc] = next
	}
	outStates := make([]ServiceRuntimeState, 0, len(services))
	for _, svc := range services {
		if st, ok := byService[svc]; ok {
			outStates = append(outStates, st)
		} else {
			outStates = append(outStates, ServiceRuntimeState{Service: svc, State: "missing"})
		}
	}
	return outStates, nil
}

// EnsureServicesUp recreates missing or unhealthy dependency services and waits for health.
// Services already running and healthy are skipped.
func (r *Runner) EnsureServicesUp(imageRef string, services ...string) error {
	if len(services) == 0 {
		return nil
	}
	states, err := r.ServiceRuntimeStates(services)
	if err != nil {
		return r.composeUp(imageRef, true, false, false, services...)
	}
	_, start, recreate := planDependencyEnsure(states)
	if len(start) == 0 && len(recreate) == 0 {
		return nil
	}
	if len(start) > 0 {
		if err := r.composeUp(imageRef, false, false, false, start...); err != nil {
			return err
		}
	}
	if len(recreate) > 0 {
		if err := r.composeUp(imageRef, false, true, false, recreate...); err != nil {
			return err
		}
	}
	return r.composeUp(imageRef, true, false, true, services...)
}

func (r *Runner) composeUp(imageRef string, wait, forceRecreate, noRecreate bool, services ...string) error {
	if len(services) == 0 {
		return nil
	}
	args := []string{"up", "-d", "--no-build", "--no-deps"}
	if wait {
		args = append(args, "--wait", "--wait-timeout", fmt.Sprintf("%d", int(ensureServicesWaitTimeout.Seconds())))
	}
	if forceRecreate {
		args = append(args, "--force-recreate")
	}
	if noRecreate {
		args = append(args, "--no-recreate")
	}
	args = append(args, services...)
	cmd, err := r.command(args...)
	if err != nil {
		return err
	}
	cmd.Env = r.envFor(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		states, stateErr := r.ServiceRuntimeStates(services)
		if stateErr == nil {
			return fmt.Errorf("compose up failed: %w%s", err, formatDependencyEnsureFailure(states))
		}
		return fmt.Errorf("compose up failed: %w", err)
	}
	return nil
}

// RunOneShot executes a one-shot compose service without starting dependencies.
func (r *Runner) RunOneShot(service, imageRef string, extraArgs ...string) error {
	args := []string{"run", "--rm", "--no-deps", service}
	args = append(args, extraArgs...)
	cmd, err := r.command(args...)
	if err != nil {
		return err
	}
	cmd.Env = r.envFor(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose run failed: %w", err)
	}
	return nil
}

// UpServiceNoDeps recreates one service without touching dependencies.
func (r *Runner) UpServiceNoDeps(service, imageRef string) error {
	cmd, err := r.command("up", "-d", "--no-deps", "--no-build", service)
	if err != nil {
		return err
	}
	cmd.Env = r.envFor(imageRef)
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}
	return nil
}

// RemoveService stops and removes one service without affecting any other
// services in the compose project.
func (r *Runner) RemoveService(service string) error {
	cmd, err := r.command("rm", "-s", "-f", service)
	if err != nil {
		return err
	}
	if err := runComposeCmd(cmd); err != nil {
		return fmt.Errorf("compose remove service failed: %w", err)
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
	return renderPortOverrideYAML(endpoints, false)
}

// RenderBlueGreenOverrideYAML builds a blue-green override that clears depends_on
// on the released service and binds reserved localhost ports. Shared long-running
// dependencies are ensured separately and reached via external networks.
func RenderBlueGreenOverrideYAML(endpoints []Endpoint) []byte {
	return renderPortOverrideYAML(endpoints, true)
}

func renderPortOverrideYAML(endpoints []Endpoint, clearDependsOn bool) []byte {
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
		b.WriteString(":\n")
		if clearDependsOn {
			b.WriteString("    depends_on: !override []\n")
		}
		b.WriteString("    ports: !override\n")
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

func (r *Runner) composePsOutput(services ...string) ([]byte, error) {
	args := []string{"ps", "--all", "--format", "json"}
	args = append(args, services...)
	cmd, err := r.command(args...)
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if detail := composeErrorDetail(stderr.String()); detail != "" {
			return nil, fmt.Errorf("compose ps failed: %s", detail)
		}
		return nil, fmt.Errorf("compose ps failed")
	}
	return out, nil
}

type composePsRow struct {
	Service string `json:"Service"`
	Name    string `json:"Name"`
}

func parseContainerNameFromPsJSON(out []byte) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row composePsRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		name := strings.TrimPrefix(row.Name, "/")
		if name != "" {
			return name, nil
		}
	}
	return "", errServiceContainerNotFound
}

var errServiceContainerNotFound = fmt.Errorf("service container not found")

const containerAppearTimeout = 30 * time.Second

// WaitForServiceContainer polls compose ps until the service container appears.
func (r *Runner) WaitForServiceContainer(service string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = containerAppearTimeout
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		name, err := r.ContainerNameForService(service)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, errServiceContainerNotFound) {
			return "", err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("%w within %s", errServiceContainerNotFound, timeout)
}

func formatBlueGreenServiceHint(project, service string) string {
	project = strings.TrimSpace(project)
	service = strings.TrimSpace(service)
	if project == "" || service == "" {
		return ""
	}
	return fmt.Sprintf(" — inspect: docker compose -p %s logs %s", project, service)
}
