package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// EnsureDepsRequest brings long-running compose dependencies to a healthy state.
type EnsureDepsRequest struct {
	Name          string
	ComposeFile   string
	ExceptService string
	ImageRef      string
	RegistryUser  string
	RegistryToken string
}

// RunServiceRequest runs a one-shot compose service after dependencies are healthy.
type RunServiceRequest struct {
	Name          string
	ComposeFile   string
	Service       string
	Args          []string
	ImageRef      string
	RegistryUser  string
	RegistryToken string
}

// DependencyServiceNames returns long-running services to ensure before release/migrate.
// One-shot services (restart: "no") and explicitly excluded names are omitted.
func DependencyServiceNames(analysis *AnalyzeResult, exclude ...string) []string {
	if analysis == nil {
		return nil
	}
	skip := map[string]bool{}
	for _, name := range exclude {
		name = strings.TrimSpace(name)
		if name != "" {
			skip[name] = true
		}
	}
	var out []string
	for _, svc := range analysis.Services {
		if svc.OneShot || skip[svc.Name] {
			continue
		}
		out = append(out, svc.Name)
	}
	sortStrings(out)
	return out
}

// ServiceDependencyNames returns the transitive long-running dependencies
// declared by target through Compose depends_on. Unrelated services and
// one-shot nodes are not returned.
func ServiceDependencyNames(analysis *AnalyzeResult, target string) []string {
	if analysis == nil {
		return nil
	}
	byName := make(map[string]ServiceSpec, len(analysis.Services))
	for _, svc := range analysis.Services {
		byName[svc.Name] = svc
	}
	if _, ok := byName[target]; !ok {
		return nil
	}

	visited := map[string]bool{target: true}
	selected := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		svc, ok := byName[name]
		if !ok {
			return
		}
		for _, dependency := range svc.DependsOn {
			if visited[dependency] {
				continue
			}
			visited[dependency] = true
			dep, ok := byName[dependency]
			if !ok {
				continue
			}
			if !dep.OneShot {
				selected[dependency] = true
			}
			visit(dependency)
		}
	}
	visit(target)

	out := make([]string, 0, len(selected))
	for name := range selected {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// EnsureDependenciesUp starts or recreates dependency services and waits for health.
func EnsureDependenciesUp(req EnsureDepsRequest, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := ValidateProjectName(req.Name); err != nil {
		return err
	}
	if !deps.ComposeAvailable() {
		return fmt.Errorf("docker compose is not installed — install docker-compose-plugin (sp setup or dashboard → Apps → Server Dependencies)")
	}

	rec, analysis, runner, err := runnerForManagedProject(req.Name, req.ComposeFile)
	if err != nil {
		return err
	}
	_ = rec

	services := DependencyServiceNames(analysis, req.ExceptService)
	if len(services) == 0 {
		progress("No long-running dependencies to ensure.")
		return nil
	}
	return ensureManagedServicesUp(runner, services, req.ImageRef, req.RegistryUser, req.RegistryToken, progress)
}

func ensureManagedServicesUp(runner Runner, services []string, imageRef, registryUser, registryToken string, progress Progress) error {
	progress("Ensuring compose dependencies are healthy: " + strings.Join(services, ", "))
	states, err := runner.ServiceRuntimeStates(services)
	if err == nil {
		logDependencyEnsurePlan(states, progress)
	}

	cleanupLogin, err := ephemeralRegistryLogin(registryUser, registryToken)
	if err != nil {
		return err
	}
	if cleanupLogin != nil {
		defer cleanupLogin()
	}

	if err := runner.EnsureServicesUp(imageRef, services...); err != nil {
		return fmt.Errorf("dependency ensure failed: %w", err)
	}
	progress("Dependencies are healthy.")
	return nil
}

// RunComposeService ensures dependencies then runs a one-shot compose service.
func RunComposeService(req RunServiceRequest, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Service = strings.TrimSpace(req.Service)
	if err := ValidateProjectName(req.Name); err != nil {
		return err
	}
	if err := ValidateServiceName(req.Service); err != nil {
		return err
	}
	if !deps.ComposeAvailable() {
		return fmt.Errorf("docker compose is not installed — install docker-compose-plugin (sp setup or dashboard → Apps → Server Dependencies)")
	}

	_, analysis, runner, err := runnerForManagedProject(req.Name, req.ComposeFile)
	if err != nil {
		return err
	}
	var service ServiceSpec
	var found bool
	for _, svc := range analysis.Services {
		if svc.Name == req.Service {
			service = svc
			found = true
			break
		}
	}
	if !found || !service.OneShot {
		return fmt.Errorf("service %q is not a one-shot service (restart: \"no\") — use sp compose release instead", req.Service)
	}

	services := ServiceDependencyNames(analysis, req.Service)
	if len(services) == 0 {
		progress("No long-running dependencies declared for " + req.Service + ".")
	} else if err := ensureManagedServicesUp(runner, services, req.ImageRef, req.RegistryUser, req.RegistryToken, progress); err != nil {
		return err
	}

	cleanupLogin, err := ephemeralRegistryLogin(req.RegistryUser, req.RegistryToken)
	if err != nil {
		return err
	}
	if cleanupLogin != nil {
		defer cleanupLogin()
	}

	progress("Running one-shot service " + req.Service + "...")
	if err := runner.RunOneShot(req.Service, req.ImageRef, req.Args...); err != nil {
		return fmt.Errorf("compose run failed: %w", err)
	}
	progress("One-shot service " + req.Service + " completed.")
	return nil
}

func ensureDependenciesReady(req ReleaseRequest, rec ProjectRecord, gen Generation, analysis *AnalyzeResult, envPath, overridePath string, progress Progress) error {
	if req.SkipEnsureDeps {
		return nil
	}
	services := DependencyServiceNames(analysis, req.Service)
	if len(services) == 0 {
		return nil
	}
	runner := Runner{
		ProjectRoot:    rec.RootDir,
		ComposeFile:    rec.ComposeFile,
		ComposeProject: gen.ComposeProject,
		ProjectEnvFile: managedEnvFile(rec.RootDir),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
	}
	progress("Ensuring compose dependencies are healthy before release...")
	states, err := runner.ServiceRuntimeStates(services)
	if err == nil {
		logDependencyEnsurePlan(states, progress)
	}
	if err := runner.EnsureServicesUp(req.ImageRef, services...); err != nil {
		return fmt.Errorf("release aborted: dependencies not healthy: %w", err)
	}
	progress("Dependencies are healthy.")
	return nil
}

func runnerForManagedProject(name, composeFile string) (ProjectRecord, *AnalyzeResult, Runner, error) {
	rec, ok, err := GetProject(name)
	if err != nil {
		return ProjectRecord{}, nil, Runner{}, err
	}
	if !ok {
		return ProjectRecord{}, nil, Runner{}, fmt.Errorf("compose project %q not found — run sp compose deploy first", name)
	}
	gen, hasGen := GetActiveGeneration(rec)
	if !hasGen {
		return ProjectRecord{}, nil, Runner{}, fmt.Errorf("compose project %q has no active generation", name)
	}
	file := composeFile
	if strings.TrimSpace(file) == "" {
		file = rec.ComposeFile
	}
	analysis, err := AnalyzeProjectStrict(name, rec.RootDir, file)
	if err != nil {
		return ProjectRecord{}, nil, Runner{}, fmt.Errorf("compose analysis failed: %w", err)
	}
	if !analysis.CanDeploy {
		return ProjectRecord{}, nil, Runner{}, fmt.Errorf("compose manifest failed policy checks")
	}
	genDir, err := GenerationDir(name, gen.ID)
	if err != nil {
		return ProjectRecord{}, nil, Runner{}, err
	}
	runner := Runner{
		ProjectRoot:    rec.RootDir,
		ComposeFile:    rec.ComposeFile,
		ComposeProject: gen.ComposeProject,
		ProjectEnvFile: managedEnvFile(rec.RootDir),
		EnvFile:        filepath.Join(genDir, "serverpilot.env"),
		OverrideFile:   filepath.Join(genDir, "serverpilot.override.yml"),
	}
	return rec, analysis, runner, nil
}

func dependencyNeedsEnsure(st ServiceRuntimeState) bool {
	if st.State == "missing" || st.State == "" {
		return true
	}
	if st.State != "running" {
		return true
	}
	switch strings.ToLower(st.Health) {
	case "", "healthy":
		return false
	default:
		return true
	}
}

func dependencyNeedsRecreate(st ServiceRuntimeState) bool {
	return st.State == "running" && strings.EqualFold(st.Health, "unhealthy")
}

func planDependencyEnsure(states []ServiceRuntimeState) (healthy, start, recreate []string) {
	for _, st := range states {
		if !dependencyNeedsEnsure(st) {
			healthy = append(healthy, st.Service)
			continue
		}
		if dependencyNeedsRecreate(st) {
			recreate = append(recreate, st.Service)
			continue
		}
		start = append(start, st.Service)
	}
	return healthy, start, recreate
}

func logDependencyEnsurePlan(states []ServiceRuntimeState, progress Progress) {
	for _, st := range states {
		health := st.Health
		if health == "" {
			health = "-"
		}
		progress(fmt.Sprintf("  %s: state=%s health=%s", st.Service, st.State, health))
	}
	healthy, start, recreate := planDependencyEnsure(states)
	if len(healthy) > 0 {
		progress("  already healthy: " + strings.Join(healthy, ", "))
	}
	if len(recreate) > 0 {
		progress("  will recreate unhealthy: " + strings.Join(recreate, ", "))
	}
	if len(start) > 0 {
		progress("  will start/wait: " + strings.Join(start, ", "))
	}
}

func formatDependencyEnsureFailure(states []ServiceRuntimeState) string {
	var failed []string
	for _, st := range states {
		if dependencyNeedsEnsure(st) {
			health := st.Health
			if health == "" {
				health = "-"
			}
			failed = append(failed, fmt.Sprintf("%s(state=%s, health=%s)", st.Service, st.State, health))
		}
	}
	if len(failed) == 0 {
		return ""
	}
	return fmt.Sprintf(
		" — services did not reach their Compose health requirements: %s; inspect their declared healthchecks and container logs",
		strings.Join(failed, ", "),
	)
}
