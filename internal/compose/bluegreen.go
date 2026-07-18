package compose

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deployhealth"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/trafficswitch"
)

const (
	StrategyRolling   = "rolling"
	StrategyBlueGreen = "blue-green"
	ColorBlue         = "blue"
	ColorGreen        = "green"
	defaultDrain      = 10 * time.Second
	defaultHealthWait = 60 * time.Second
)

// ParseStrategy normalizes a deployment strategy name.
func ParseStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "blue-green", "bluegreen", "bg":
		return StrategyBlueGreen
	default:
		return StrategyRolling
	}
}

// ReleaseServiceBlueGreen deploys the inactive color in parallel, validates health,
// repoints nginx, drains, and removes the previous color.
func ReleaseServiceBlueGreen(req ReleaseRequest, rec ProjectRecord, gen Generation, analysis *AnalyzeResult, progress Progress) error {
	if err := analysisAllowsBlueGreen(analysis); err != nil {
		return err
	}
	currentColor := normalizeColor(gen.Color)
	targetColor := oppositeColor(currentColor)
	progress(fmt.Sprintf("Blue-green release: bringing up %s color (%s)...", targetColor, colorProjectName(req.Name, targetColor)))

	genID, err := NewGenerationID()
	if err != nil {
		return err
	}
	genDir, err := GenerationDir(req.Name, genID)
	if err != nil {
		return err
	}

	ownerPorts, endpoints, createdOwners, err := reserveColorEndpoints(req.Name, targetColor, analysis.Endpoints)
	if err != nil {
		return err
	}

	envPath, err := writeDeployEnv(genDir, ownerPorts)
	if err != nil {
		portalloc.ReleaseOwners(createdOwners)
		return err
	}
	overridePath, err := WriteOverride(genDir, "serverpilot.override.yml", RenderPortOverrideYAML(endpoints))
	if err != nil {
		portalloc.ReleaseOwners(createdOwners)
		return err
	}

	targetRunner := Runner{
		ProjectRoot:    rec.RootDir,
		ComposeFile:    rec.ComposeFile,
		ComposeProject: colorProjectName(req.Name, targetColor),
		ProjectEnvFile: managedEnvFile(rec.RootDir),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
	}
	if err := targetRunner.PullService(req.Service, req.ImageRef); err != nil {
		portalloc.ReleaseOwners(createdOwners)
		return err
	}
	if err := targetRunner.Up(req.ImageRef); err != nil {
		_ = targetRunner.Down(false)
		portalloc.ReleaseOwners(createdOwners)
		return err
	}

	healthTimeout := req.HealthTimeout
	if healthTimeout <= 0 {
		healthTimeout = defaultHealthWait
	}
	for _, ep := range endpoints {
		containerName, err := targetRunner.ContainerNameForService(ep.Service)
		if err != nil {
			_ = targetRunner.Down(false)
			portalloc.ReleaseOwners(createdOwners)
			return fmt.Errorf("blue-green health: %w", err)
		}
		if err := deployhealth.WaitHealthy(deployhealth.Options{
			ContainerName: containerName,
			HostPort:      ep.HostPort,
			HealthURL:     req.HealthURL,
			Timeout:       healthTimeout,
		}); err != nil {
			_ = targetRunner.Down(false)
			portalloc.ReleaseOwners(createdOwners)
			return fmt.Errorf("blue-green health check failed for %s: %w", ep.Service, err)
		}
	}

	oldPorts := endpointPortMap(gen.Endpoints)
	switches := make([]trafficswitch.PortSwitch, 0, len(endpoints))
	for _, ep := range endpoints {
		oldPort, ok := oldPorts[endpointKey(ep)]
		if !ok {
			continue
		}
		switches = append(switches, trafficswitch.PortSwitch{OldPort: oldPort, NewPort: ep.HostPort})
	}
	if err := trafficswitch.RepointComposeProject(req.Name, switches); err != nil {
		_ = targetRunner.Down(false)
		portalloc.ReleaseOwners(createdOwners)
		return err
	}

	drain := req.Drain
	if drain <= 0 {
		drain = defaultDrain
	}
	if drain > 0 {
		progress(fmt.Sprintf("Draining connections for %s...", drain))
		time.Sleep(drain)
	}

	if hasGen, oldRunner := activeColorRunner(rec, gen); hasGen {
		progress("Stopping previous " + currentColor + " color...")
		_ = oldRunner.Down(false)
		portalloc.ReleaseColorOwners(req.Name, currentColor)
	}

	now := time.Now().UTC()
	newGen := Generation{
		ID:             genID,
		Number:         gen.Number + 1,
		ComposeProject: colorProjectName(req.Name, targetColor),
		Color:          targetColor,
		Fingerprint:    analysis.Fingerprint,
		State:          StateActive,
		Endpoints:      endpoints,
		CreatedAt:      now,
		PromotedAt:     now,
	}
	rec.ActiveGenID = genID
	rec.Generations = append(rec.Generations, newGen)
	rec.UpdatedAt = now
	if err := UpsertProject(rec); err != nil {
		return err
	}
	progress("Blue-green release complete — active color is now " + targetColor + ".")
	return nil
}

func reserveColorEndpoints(project, color string, endpoints []Endpoint) (map[string]int, []Endpoint, []string, error) {
	requests := make([]portalloc.PortOwnerRequest, 0, len(endpoints))
	for _, ep := range endpoints {
		owner := portalloc.ComposeColorOwner(project, color, ep.Service, ep.ContainerPort, ep.Protocol)
		requests = append(requests, portalloc.PortOwnerRequest{Owner: owner})
	}
	ports, created, err := portalloc.ReserveOwnersTracked(requests, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]Endpoint, 0, len(endpoints))
	envMap := map[string]int{}
	for _, ep := range endpoints {
		owner := portalloc.ComposeColorOwner(project, color, ep.Service, ep.ContainerPort, ep.Protocol)
		port := ports[owner]
		ep.HostPort = port
		out = append(out, ep)
		envMap[ep.EnvVar] = port
	}
	return envMap, out, created, nil
}

func colorProjectName(project, color string) string {
	return project + "__" + color
}

func normalizeColor(color string) string {
	if strings.EqualFold(strings.TrimSpace(color), ColorGreen) {
		return ColorGreen
	}
	return ColorBlue
}

func oppositeColor(color string) string {
	if color == ColorGreen {
		return ColorBlue
	}
	return ColorGreen
}

func analysisAllowsBlueGreen(analysis *AnalyzeResult) error {
	for _, m := range analysis.Mounts {
		if !m.Supported {
			continue
		}
		if m.Type == "volume" || m.Type == "bind" {
			return fmt.Errorf("compose stack has persistent mounts — use --strategy rolling for stateful stacks")
		}
	}
	return nil
}

func endpointKey(ep Endpoint) string {
	return ep.Service + ":" + ep.ContainerPort + "/" + ep.Protocol
}

func endpointPortMap(endpoints []Endpoint) map[string]int {
	out := make(map[string]int, len(endpoints))
	for _, ep := range endpoints {
		out[endpointKey(ep)] = ep.HostPort
	}
	return out
}

func activeColorRunner(rec ProjectRecord, gen Generation) (bool, Runner) {
	runner := Runner{
		ProjectRoot:    rec.RootDir,
		ComposeFile:    rec.ComposeFile,
		ComposeProject: gen.ComposeProject,
		ProjectEnvFile: managedEnvFile(rec.RootDir),
	}
	if gen.ID != "" {
		if genDir, err := GenerationDir(rec.Name, gen.ID); err == nil {
			runner.EnvFile = filepath.Join(genDir, "serverpilot.env")
			runner.OverrideFile = filepath.Join(genDir, "serverpilot.override.yml")
		}
	}
	return gen.ComposeProject != "", runner
}

type composePsRow struct {
	Service string `json:"Service"`
	Name    string `json:"Name"`
}

// ContainerNameForService returns the running container name for a compose service.
func (r *Runner) ContainerNameForService(service string) (string, error) {
	cmd, err := r.command("ps", "--format", "json", service)
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("compose ps failed")
	}
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
	return "", fmt.Errorf("service container not found")
}
