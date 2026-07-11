package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

// Progress reports user-facing operation messages.
type Progress func(string)

// Deploy deploys or updates a managed compose project generation.
func Deploy(req DeployRequest, progress Progress) (*ProjectRecord, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !deps.ComposeAvailable() {
		return nil, fmt.Errorf("docker compose is not installed")
	}

	analysis, err := AnalyzeProjectStrict(req.Name, req.RootDir, req.ComposeFile)
	if err != nil {
		return nil, err
	}
	if !analysis.CanDeploy {
		return nil, fmt.Errorf("compose project failed policy checks")
	}
	if len(analysis.Endpoints) == 0 {
		return nil, fmt.Errorf("compose project has no publishable endpoints")
	}

	existing, hasProject, err := GetProject(req.Name)
	if err != nil {
		return nil, err
	}
	genID, err := NewGenerationID()
	if err != nil {
		return nil, err
	}
	genNumber := 1
	composeProject := req.Name
	if hasProject {
		genNumber = len(existing.Generations) + 1
		composeProject = existing.Generations[0].ComposeProject
		if composeProject == "" {
			composeProject = req.Name
		}
	}

	progress("Reserving host ports...")
	ownerPorts, endpoints, owners, err := reserveEndpoints(req.Name, genID, analysis.Endpoints)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	genDir, err := GenerationDir(req.Name, genID)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	envPath, err := writeDeployEnv(genDir, ownerPorts)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	overrideContent := RenderPortOverrideYAML(endpoints)
	overridePath, err := WriteOverride(genDir, "serverpilot.override.yml", overrideContent)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	runner := Runner{
		ProjectRoot:    analysis.ProjectRoot,
		ComposeFile:    analysis.ComposeFile,
		ComposeProject: composeProject,
		ProjectEnvFile: managedEnvFile(analysis.ProjectRoot),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
	}
	cleanupLogin, err := ephemeralRegistryLogin(req.RegistryUser, req.RegistryToken)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	if cleanupLogin != nil {
		defer cleanupLogin()
	}
	progress("Starting compose stack...")
	if err := runner.Up(req.AppImageRef); err != nil {
		_ = runner.Down(false)
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	now := time.Now().UTC()
	gen := Generation{
		ID:             genID,
		Number:         genNumber,
		ComposeProject: composeProject,
		Fingerprint:    analysis.Fingerprint,
		State:          StateActive,
		Endpoints:      endpoints,
		CreatedAt:      now,
		PromotedAt:     now,
	}

	rec := ProjectRecord{
		Name:        req.Name,
		Alias:       strings.TrimSpace(req.Alias),
		RootDir:     analysis.ProjectRoot,
		ComposeFile: analysis.ComposeFile,
		ActiveGenID: genID,
		Generations: []Generation{gen},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if hasProject {
		rec = existing
		rec.Alias = firstNonEmpty(strings.TrimSpace(req.Alias), rec.Alias)
		rec.RootDir = analysis.ProjectRoot
		rec.ComposeFile = analysis.ComposeFile
		rec.ActiveGenID = genID
		rec.Generations = append(rec.Generations, gen)
		rec.UpdatedAt = now
	}
	if err := UpsertProject(rec); err != nil {
		_ = runner.Down(false)
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	progress("Compose project deployed.")
	return &rec, nil
}

func reserveEndpoints(project, generation string, endpoints []Endpoint) (map[string]int, []Endpoint, []string, error) {
	requests := make([]portalloc.PortOwnerRequest, 0, len(endpoints))
	for _, ep := range endpoints {
		owner := portalloc.ComposeOwner(project, generation, ep.Service, ep.ContainerPort)
		requests = append(requests, portalloc.PortOwnerRequest{Owner: owner})
	}
	ports, err := portalloc.ReserveOwners(requests, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		return nil, nil, nil, err
	}
	owners := make([]string, 0, len(requests))
	out := make([]Endpoint, 0, len(endpoints))
	envMap := map[string]int{}
	for _, ep := range endpoints {
		owner := portalloc.ComposeOwner(project, generation, ep.Service, ep.ContainerPort)
		owners = append(owners, owner)
		port := ports[owner]
		ep.HostPort = port
		out = append(out, ep)
		envMap[ep.EnvVar] = port
	}
	return envMap, out, owners, nil
}

func writeDeployEnv(dir string, ports map[string]int) (string, error) {
	var b strings.Builder
	for key, port := range ports {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(fmt.Sprintf("%d", port))
		b.WriteString("\n")
	}
	if len(ports) == 1 {
		for _, port := range ports {
			b.WriteString(DefaultEndpointEnvVar)
			b.WriteString("=")
			b.WriteString(fmt.Sprintf("%d", port))
			b.WriteString("\n")
		}
	}
	path := filepath.Join(dir, "serverpilot.env")
	tmp, err := os.CreateTemp(dir, ".env-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// RefreshOutdatedFlags marks clone projects outdated when parent generation changed.
func RefreshOutdatedFlags() error {
	return withRegistry(func(reg *projectRegistry) error {
		parentFP := map[string]string{}
		parentGen := map[string]string{}
		for _, p := range reg.Projects {
			if p.CloneParentID != "" {
				continue
			}
			for _, g := range p.Generations {
				if g.ID == p.ActiveGenID {
					parentFP[p.Name] = g.Fingerprint
					parentGen[p.Name] = g.ID
				}
			}
		}
		for i, p := range reg.Projects {
			if p.CloneParentID == "" {
				continue
			}
			fp := parentFP[p.CloneParentID]
			gen := parentGen[p.CloneParentID]
			p.Outdated = fp != "" && (p.CloneParentGen != gen)
			reg.Projects[i] = p
		}
		return nil
	})
}

// GetActiveGeneration returns the active generation for a project.
func GetActiveGeneration(rec ProjectRecord) (Generation, bool) {
	for _, g := range rec.Generations {
		if g.ID == rec.ActiveGenID {
			return g, true
		}
	}
	if len(rec.Generations) > 0 {
		return rec.Generations[len(rec.Generations)-1], true
	}
	return Generation{}, false
}

// DeleteProjectStack removes the active compose stack and registry entry.
func DeleteProjectStack(name string, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	rec, ok, err := GetProject(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("compose project not found")
	}
	gen, hasGen := GetActiveGeneration(rec)
	if hasGen {
		runner := Runner{
			ProjectRoot:    rec.RootDir,
			ComposeFile:    rec.ComposeFile,
			ComposeProject: gen.ComposeProject,
		}
		progress("Stopping compose stack...")
		_ = runner.Down(true)
		for _, ep := range gen.Endpoints {
			_ = portalloc.ReleaseOwner(portalloc.ComposeOwner(name, gen.ID, ep.Service, ep.ContainerPort))
		}
	}
	return DeleteProject(name)
}
