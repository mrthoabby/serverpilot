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

	progress("Ensuring compose dependencies are healthy: " + strings.Join(services, ", "))
	states, err := runner.ServiceRuntimeStates(services)
	if err == nil {
		for _, st := range states {
			if st.State != "" && st.State != "running" {
				progress(fmt.Sprintf("  %s: %s", st.Service, st.State))
			}
		}
	}

	cleanupLogin, err := ephemeralRegistryLogin(req.RegistryUser, req.RegistryToken)
	if err != nil {
		return err
	}
	if cleanupLogin != nil {
		defer cleanupLogin()
	}

	if err := runner.EnsureServicesUp(req.ImageRef, services...); err != nil {
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

	if err := EnsureDependenciesUp(EnsureDepsRequest{
		Name:          req.Name,
		ComposeFile:   req.ComposeFile,
		ImageRef:      req.ImageRef,
		RegistryUser:  req.RegistryUser,
		RegistryToken: req.RegistryToken,
	}, progress); err != nil {
		return err
	}

	_, analysis, runner, err := runnerForManagedProject(req.Name, req.ComposeFile)
	if err != nil {
		return err
	}
	var oneShot bool
	for _, svc := range analysis.Services {
		if svc.Name == req.Service {
			oneShot = svc.OneShot
			break
		}
	}
	if !oneShot {
		return fmt.Errorf("service %q is not a one-shot service (restart: \"no\") — use sp compose release instead", req.Service)
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
		for _, st := range states {
			if st.State != "" && st.State != "running" {
				progress(fmt.Sprintf("  %s: %s", st.Service, st.State))
			}
		}
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
