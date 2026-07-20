package compose

import (
	"fmt"
	"path/filepath"
	"strconv"
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
	targetService, err := serviceForBlueGreen(analysis, req.Service)
	if err != nil {
		return err
	}
	if err := validateSharedExternalNetworks(targetService); err != nil {
		return err
	}
	if err := analysisAllowsBlueGreen(targetService); err != nil {
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

	ownerPorts, endpoints, createdOwners, err := reserveColorEndpoints(req.Name, targetColor, targetService.Endpoints)
	if err != nil {
		return err
	}

	envPath, err := writeDeployEnv(genDir, ownerPorts)
	if err != nil {
		portalloc.ReleaseOwners(createdOwners)
		return err
	}
	overridePath, err := WriteOverride(genDir, "serverpilot.override.yml", RenderBlueGreenOverrideYAML(endpoints))
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
		ImageRef:       req.ImageRef,
	}
	if err := targetRunner.PullService(req.Service, req.ImageRef); err != nil {
		portalloc.ReleaseOwners(createdOwners)
		return err
	}
	if err := targetRunner.UpServiceNoDeps(req.Service, req.ImageRef); err != nil {
		_ = targetRunner.RemoveService(req.Service)
		portalloc.ReleaseOwners(createdOwners)
		return err
	}

	containerName, err := targetRunner.WaitForServiceContainer(req.Service, containerAppearTimeout)
	if err != nil {
		_ = targetRunner.RemoveService(req.Service)
		portalloc.ReleaseOwners(createdOwners)
		return fmt.Errorf("blue-green health: %w%s", err, formatBlueGreenServiceHint(targetRunner.ComposeProject, req.Service))
	}

	healthTimeout := req.HealthTimeout
	if healthTimeout <= 0 {
		healthTimeout = defaultHealthWait
	}
	if err := waitBlueGreenHealthy(req, containerName, endpoints, healthTimeout); err != nil {
		_ = targetRunner.RemoveService(req.Service)
		portalloc.ReleaseOwners(createdOwners)
		return fmt.Errorf("blue-green health check failed for %s: %w%s", req.Service, err, formatBlueGreenServiceHint(targetRunner.ComposeProject, req.Service))
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
	rollbackSites, err := trafficswitch.RepointComposeProjectWithRollback(req.Name, switches)
	if err != nil {
		_ = targetRunner.RemoveService(req.Service)
		portalloc.ReleaseOwners(createdOwners)
		return err
	}

	now := time.Now().UTC()
	newGen := Generation{
		ID:             genID,
		Number:         gen.Number + 1,
		ComposeProject: colorProjectName(req.Name, targetColor),
		Color:          targetColor,
		Fingerprint:    analysis.Fingerprint,
		State:          StateActive,
		Endpoints:      mergeGenerationEndpoints(gen.Endpoints, endpoints, req.Service),
		CreatedAt:      now,
		PromotedAt:     now,
	}
	rec.ActiveGenID = genID
	rec.Generations = append(rec.Generations, newGen)
	rec.UpdatedAt = now
	if err := UpsertProject(rec); err != nil {
		_ = rollbackSites()
		_ = targetRunner.RemoveService(req.Service)
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
		if err := oldRunner.RemoveService(req.Service); err != nil {
			return fmt.Errorf("blue-green cleanup previous service: %w", err)
		}
		releasePreviousEndpointOwners(req.Name, gen, endpoints)
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

func analysisAllowsBlueGreen(service ServiceSpec) error {
	for _, m := range service.Mounts {
		if !m.Supported {
			continue
		}
		if m.Type == "volume" || m.Type == "bind" {
			return fmt.Errorf("service %q has persistent mounts — use --strategy rolling for stateful services", service.Name)
		}
	}
	return nil
}

func serviceForBlueGreen(analysis *AnalyzeResult, name string) (ServiceSpec, error) {
	for _, service := range analysis.Services {
		if service.Name != name {
			continue
		}
		if len(service.Endpoints) == 0 {
			return ServiceSpec{}, fmt.Errorf("service %q has no published endpoints to switch", name)
		}
		return service, nil
	}
	return ServiceSpec{}, fmt.Errorf("service %q not found in compose manifest", name)
}

func validateSharedExternalNetworks(service ServiceSpec) error {
	if len(service.Networks) == 0 {
		return fmt.Errorf("service %q must declare a named external shared network for blue-green", service.Name)
	}
	for _, network := range service.Networks {
		if !network.External || strings.TrimSpace(network.RuntimeName) == "" {
			return fmt.Errorf("service %q must use only named external networks for blue-green", service.Name)
		}
	}
	return nil
}

func mergeGenerationEndpoints(previous, replacement []Endpoint, service string) []Endpoint {
	out := make([]Endpoint, 0, len(previous)+len(replacement))
	for _, endpoint := range previous {
		if endpoint.Service != service {
			out = append(out, endpoint)
		}
	}
	return append(out, replacement...)
}

func waitBlueGreenHealthy(req ReleaseRequest, containerName string, endpoints []Endpoint, timeout time.Duration) error {
	if strings.TrimSpace(req.HealthURL) != "" {
		ep, ok := primaryHealthEndpoint(endpoints)
		if !ok {
			return fmt.Errorf("no endpoints configured for health check")
		}
		return deployhealth.WaitHealthy(deployhealth.Options{
			ContainerName: containerName,
			HostPort:      ep.HostPort,
			HealthURL:     req.HealthURL,
			Timeout:       timeout,
		})
	}
	for _, ep := range endpoints {
		if err := deployhealth.WaitHealthy(deployhealth.Options{
			ContainerName: containerName,
			HostPort:      ep.HostPort,
			Timeout:       timeout,
		}); err != nil {
			return fmt.Errorf("port %s: %w", ep.ContainerPort, err)
		}
	}
	return nil
}

func primaryHealthEndpoint(endpoints []Endpoint) (Endpoint, bool) {
	if len(endpoints) == 0 {
		return Endpoint{}, false
	}
	primary := endpoints[0]
	primaryPort := endpointPortNumber(primary.ContainerPort)
	for _, ep := range endpoints[1:] {
		if port := endpointPortNumber(ep.ContainerPort); port < primaryPort {
			primary = ep
			primaryPort = port
		}
	}
	return primary, true
}

func endpointPortNumber(raw string) int {
	raw = strings.TrimSpace(strings.Split(raw, "/")[0])
	port, _ := strconv.Atoi(raw)
	return port
}

func releasePreviousEndpointOwners(project string, previous Generation, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		if previous.Color == "" {
			_ = portalloc.ReleaseOwner(endpointOwner(project, endpoint))
			continue
		}
		_ = portalloc.ReleaseOwner(portalloc.ComposeColorOwner(project, previous.Color, endpoint.Service, endpoint.ContainerPort, endpoint.Protocol))
	}
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

// ContainerNameForService returns the container name for a compose service.
func (r *Runner) ContainerNameForService(service string) (string, error) {
	out, err := r.composePsOutput(service)
	if err != nil {
		return "", err
	}
	return parseContainerNameFromPsJSON(out)
}
