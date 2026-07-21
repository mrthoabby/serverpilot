package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

type endpointReconcilePlan struct {
	Endpoints  []Endpoint
	Previous   []*Endpoint
	Stale      []Endpoint
	NewIndexes []int
}

func buildEndpointReconcilePlan(previous, next []Endpoint) endpointReconcilePlan {
	plan := endpointReconcilePlan{
		Endpoints: make([]Endpoint, len(next)),
		Previous:  make([]*Endpoint, len(next)),
	}
	copy(plan.Endpoints, next)
	used := make([]bool, len(previous))

	for nextIndex := range plan.Endpoints {
		for previousIndex := range previous {
			if used[previousIndex] || !sameEndpoint(previous[previousIndex], plan.Endpoints[nextIndex]) {
				continue
			}
			used[previousIndex] = true
			old := previous[previousIndex]
			plan.Endpoints[nextIndex].HostPort = old.HostPort
			plan.Previous[nextIndex] = &old
			break
		}
	}

	for nextIndex := range plan.Endpoints {
		if plan.Previous[nextIndex] != nil {
			continue
		}
		for previousIndex := range previous {
			if used[previousIndex] || !sameEndpointRole(previous[previousIndex], plan.Endpoints[nextIndex]) {
				continue
			}
			used[previousIndex] = true
			old := previous[previousIndex]
			plan.Endpoints[nextIndex].HostPort = old.HostPort
			plan.Previous[nextIndex] = &old
			break
		}
		if plan.Previous[nextIndex] == nil {
			plan.NewIndexes = append(plan.NewIndexes, nextIndex)
		}
	}

	for index, endpoint := range previous {
		if !used[index] {
			plan.Stale = append(plan.Stale, endpoint)
		}
	}
	return plan
}

func sameEndpoint(left, right Endpoint) bool {
	return left.Service == right.Service &&
		left.ContainerPort == right.ContainerPort &&
		left.Protocol == right.Protocol
}

func sameEndpointRole(left, right Endpoint) bool {
	return left.Service == right.Service && left.Protocol == right.Protocol
}

func reconcileReleaseStack(req ReleaseRequest, rec ProjectRecord, gen Generation, analysis *AnalyzeResult, progress Progress) error {
	migrateComposePortOwners(req.Name, rec)
	plan := buildEndpointReconcilePlan(gen.Endpoints, analysis.Endpoints)
	allocatedOwners := make([]string, 0, len(plan.NewIndexes))
	transferred := make([]struct {
		from string
		to   string
	}, 0)

	rollbackReservations := func() {
		for _, owner := range allocatedOwners {
			_ = portalloc.ReleaseOwner(owner)
		}
		for _, move := range transferred {
			_ = portalloc.TransferOwner(move.to, move.from)
		}
	}

	for index, previous := range plan.Previous {
		if previous == nil || sameEndpoint(*previous, plan.Endpoints[index]) {
			continue
		}
		oldOwner := endpointOwner(req.Name, *previous)
		newOwner := endpointOwner(req.Name, plan.Endpoints[index])
		if oldOwner == newOwner {
			continue
		}
		if err := portalloc.TransferOwner(oldOwner, newOwner); err != nil {
			rollbackReservations()
			return fmt.Errorf("release stack reconcile: transfer endpoint port: %w", err)
		}
		transferred = append(transferred, struct {
			from string
			to   string
		}{from: oldOwner, to: newOwner})
	}

	for _, index := range plan.NewIndexes {
		endpoint := plan.Endpoints[index]
		owner := endpointOwner(req.Name, endpoint)
		result, err := portalloc.ReserveOwnerWithMeta(owner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
		if err != nil {
			rollbackReservations()
			return fmt.Errorf("release stack reconcile: reserve endpoint: %w", err)
		}
		plan.Endpoints[index].HostPort = result.Port
		if result.Created {
			allocatedOwners = append(allocatedOwners, owner)
		}
	}

	genDir, err := GenerationDir(req.Name, gen.ID)
	if err != nil {
		rollbackReservations()
		return err
	}
	envPath := filepath.Join(genDir, "serverpilot.env")
	overridePath := filepath.Join(genDir, "serverpilot.override.yml")
	oldEnv, envErr := os.ReadFile(envPath)
	oldOverride, overrideErr := os.ReadFile(overridePath)

	ports := make(map[string]int, len(plan.Endpoints))
	for _, endpoint := range plan.Endpoints {
		ports[endpoint.EnvVar] = endpoint.HostPort
	}
	if _, err := writeDeployEnv(genDir, ports, req.ImageRef); err != nil {
		rollbackReservations()
		return err
	}
	if _, err := WriteOverride(genDir, "serverpilot.override.yml", RenderPortOverrideYAML(plan.Endpoints)); err != nil {
		restoreReconcileArtifacts(envPath, oldEnv, envErr, overridePath, oldOverride, overrideErr)
		rollbackReservations()
		return err
	}

	runner := Runner{
		ProjectRoot:    analysis.ProjectRoot,
		ComposeFile:    analysis.ComposeFile,
		ComposeProject: gen.ComposeProject,
		ProjectEnvFile: managedEnvFile(analysis.ProjectRoot),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
		ImageRef:       req.ImageRef,
	}
	progress("Compose manifest changed; reconciling the complete stack...")
	if err := runner.PullService(req.Service, req.ImageRef); err != nil {
		restoreReconcileArtifacts(envPath, oldEnv, envErr, overridePath, oldOverride, overrideErr)
		rollbackReservations()
		return err
	}
	if err := runner.Up(req.ImageRef); err != nil {
		restoreReconcileArtifacts(envPath, oldEnv, envErr, overridePath, oldOverride, overrideErr)
		rollbackReservations()
		return err
	}

	for _, endpoint := range plan.Stale {
		_ = portalloc.ReleaseOwner(endpointOwner(req.Name, endpoint))
	}

	gen.Fingerprint = analysis.Fingerprint
	gen.Endpoints = plan.Endpoints
	gen.PromotedAt = time.Now().UTC()
	for index := range rec.Generations {
		if rec.Generations[index].ID == gen.ID {
			rec.Generations[index] = gen
			break
		}
	}
	rec.RootDir = analysis.ProjectRoot
	rec.ComposeFile = analysis.ComposeFile
	if err := UpsertProject(rec); err != nil {
		return fmt.Errorf("release stack reconcile: update registry: %w", err)
	}
	progress("Stack reconcile complete.")
	return nil
}

func endpointOwner(project string, endpoint Endpoint) string {
	return portalloc.ComposeStableOwner(project, endpoint.Service, endpoint.ContainerPort, endpoint.Protocol)
}

func restoreReconcileArtifacts(envPath string, env []byte, envErr error, overridePath string, override []byte, overrideErr error) {
	if envErr == nil {
		_ = atomicRestoreReconcileArtifact(envPath, env)
	}
	if overrideErr == nil {
		_ = atomicRestoreReconcileArtifact(overridePath, override)
	}
}

func atomicRestoreReconcileArtifact(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".reconcile-restore-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
