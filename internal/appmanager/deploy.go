package appmanager

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deployhealth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/mapper"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

const runtimeDir = "/var/lib/serverpilot/appmanager/tmp"

func (s *Service) Deploy(ctx context.Context, environmentID, artifactID, trigger, actor string) (Deployment, error) {
	if trigger != "manual" && trigger != "auto" && trigger != "rollback" {
		return Deployment{}, fmt.Errorf("%w: invalid deployment trigger", ErrInvalid)
	}
	if actor == "" || len(actor) > 100 || strings.ContainsAny(actor, "\r\n") {
		return Deployment{}, fmt.Errorf("%w: invalid deployment actor", ErrInvalid)
	}
	env, artifact, _, err := s.artifactForDeployment(ctx, environmentID, artifactID)
	if err != nil {
		return Deployment{}, err
	}
	if artifact.Status != ArtifactReady {
		return Deployment{}, fmt.Errorf("%w: image artifact is not ready", ErrConflict)
	}
	id, err := newID()
	if err != nil {
		return Deployment{}, err
	}
	_, err = s.store.db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,artifact_id,status,trigger,actor,created_at) VALUES(?,?,?,?,?,?,?)`, id, environmentID, artifactID, DeploymentQueued, trigger, actor, s.now())
	if err != nil {
		return Deployment{}, mapConstraintError(err, "an active deployment already exists")
	}
	if env.AgentID != nil {
		if err := s.queueAgentDeploy(ctx, *env.AgentID, id); err != nil {
			_ = s.failDeployment(ctx, id, "agent_queue_failed")
			return Deployment{}, err
		}
		return s.GetDeployment(ctx, id)
	}
	// Local work is claimed by the bounded background reconciler. Keeping the
	// HTTP request out of the Docker lifecycle avoids client cancellation in the
	// middle of a privileged update.
	return s.GetDeployment(ctx, id)
}

// Rollback deploys the most recent successful artifact before the one that is
// currently active. The stored digest keeps the rollback immutable.
func (s *Service) Rollback(ctx context.Context, environmentID, actor string) (Deployment, error) {
	if !validID(environmentID) {
		return Deployment{}, fmt.Errorf("%w: invalid environment", ErrInvalid)
	}
	var artifactID string
	err := s.store.db.QueryRowContext(ctx, `SELECT d.artifact_id FROM deployments d JOIN application_environments e ON e.id=d.environment_id JOIN application_release_artifacts ara ON ara.id=d.artifact_id WHERE d.environment_id=? AND d.status='success' AND ara.status='ready' AND ara.image_digest<>'' AND (e.current_artifact_id IS NULL OR d.artifact_id<>e.current_artifact_id) ORDER BY d.finished_at DESC LIMIT 1`, environmentID).Scan(&artifactID)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, fmt.Errorf("%w: no rollback release", ErrNotFound)
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("load rollback release: %w", err)
	}
	return s.Deploy(ctx, environmentID, artifactID, "rollback", actor)
}

func (s *Service) runLocalDeployment(ctx context.Context, deploymentID string) error {
	var environmentID, artifactID string
	res, err := s.store.db.ExecContext(ctx, `UPDATE deployments SET status='running',started_at=? WHERE id=? AND status='queued'`, s.now(), deploymentID)
	if err != nil {
		return fmt.Errorf("start deployment: %w", err)
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return fmt.Errorf("%w: deployment is not queued", ErrConflict)
	}
	if err := s.store.db.QueryRowContext(ctx, `SELECT environment_id,artifact_id FROM deployments WHERE id=?`, deploymentID).Scan(&environmentID, &artifactID); err != nil {
		return s.failDeployment(ctx, deploymentID, "deployment_load_failed")
	}
	env, artifact, app, err := s.artifactForDeployment(ctx, environmentID, artifactID)
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "target_load_failed")
	}
	variables, err := s.ResolveEnvironmentVariables(ctx, environmentID)
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "configuration_failed")
	}
	image, err := deploymentImage(app.ImageName, artifact)
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "image_invalid")
	}
	envFile, cleanup, err := writeRuntimeEnvFile(environmentID, variables)
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "environment_file_failed")
	}
	defer cleanup()
	if err := s.pullImage(ctx, image); err != nil {
		return s.failDeployment(ctx, deploymentID, "image_pull_failed")
	}
	port := env.HostPort
	if port == 0 {
		port, err = portalloc.ReserveOwner("appmanager:"+env.ID, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
		if err != nil {
			return s.failDeployment(ctx, deploymentID, "port_reservation_failed")
		}
	}
	actualName := env.ContainerName
	if env.CurrentArtifactID == nil {
		actualName = env.ContainerName + "__blue"
		err = s.firstRun(ctx, env, app, actualName, image, port, envFile)
	} else if env.SiteEnabled {
		err = docker.ReleaseBlueGreenProgress(docker.BlueGreenRequest{Container: env.ContainerName, Image: image, EnvFile: envFile, HealthURL: env.HealthPath, HealthTimeout: 90 * time.Second, Drain: 10 * time.Second}, func(string) {})
		if err == nil {
			actualName = nextColorName(env.ContainerName)
		}
	} else {
		err = s.replaceWithoutSite(ctx, env.ContainerName, image, port, env.ContainerPort, env.HealthPath, envFile, app.ID, env.ID)
	}
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "deployment_failed")
	}
	now := s.now()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return s.failDeployment(ctx, deploymentID, "persistence_failed")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE application_environments SET container_name=?,host_port=?,current_artifact_id=?,status='healthy',last_deployment_at=?,updated_at=? WHERE id=?`, actualName, port, artifact.ID, now, now, env.ID); err != nil {
		return s.failDeployment(ctx, deploymentID, "persistence_failed")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE deployments SET status='success',container_name=?,image_digest=?,log_summary='Deployment completed',finished_at=? WHERE id=?`, actualName, artifact.ImageDigest, now, deploymentID); err != nil {
		return s.failDeployment(ctx, deploymentID, "persistence_failed")
	}
	if err = insertAudit(ctx, tx, "system", "deployment.success", "deployment", deploymentID, ""); err != nil {
		return s.failDeployment(ctx, deploymentID, "persistence_failed")
	}
	if err = tx.Commit(); err != nil {
		return s.failDeployment(ctx, deploymentID, "persistence_failed")
	}
	return nil
}

func deploymentImage(repository string, artifact ApplicationReleaseArtifact) (string, error) {
	if artifact.ImageDigest != "" {
		return ImageReference(repository, "", artifact.ImageDigest)
	}
	idx := strings.LastIndex(artifact.ImageReference, ":")
	if idx < 0 {
		return "", fmt.Errorf("invalid artifact image")
	}
	return ImageReference(repository, artifact.ImageReference[idx+1:], "")
}

func (s *Service) pullImage(ctx context.Context, image string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	conn, connErr := s.GitHubConnection(ctx)
	_, _, pat, secretErr := s.githubSecrets(ctx)
	configDir, err := os.MkdirTemp(runtimeDir, "docker-config-")
	if err != nil {
		return fmt.Errorf("create registry session")
	}
	defer os.RemoveAll(configDir)
	if err := os.Chmod(configDir, 0o700); err != nil {
		return fmt.Errorf("secure registry session")
	}
	if connErr == nil && secretErr == nil && pat != "" {
		loginCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(loginCtx, dockerBin, "--config", configDir, "login", "ghcr.io", "--username", conn.RegistryUsername, "--password-stdin")
		cmd.Stdin = strings.NewReader(pat + "\n")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("registry authentication failed")
		}
	}
	pullCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := exec.CommandContext(pullCtx, dockerBin, "--config", configDir, "pull", "--", image).Run(); err != nil {
		return fmt.Errorf("image pull failed")
	}
	return nil
}

func writeRuntimeEnvFile(environmentID string, variables []ResolvedVariable) (string, func(), error) {
	if !validID(environmentID) {
		return "", func() {}, fmt.Errorf("invalid environment")
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("create runtime directory")
	}
	f, err := os.CreateTemp(runtimeDir, "env-"+environmentID[:8]+"-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create environment file")
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("secure environment file")
	}
	w := bufio.NewWriter(f)
	for _, item := range variables {
		if !validEnvKey(item.Key) || strings.ContainsAny(item.Value, "\x00\r\n") {
			_ = f.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("invalid environment value")
		}
		if _, err := w.WriteString(item.Key + "=" + item.Value + "\n"); err != nil {
			_ = f.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("write environment file")
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write environment file")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("sync environment file")
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close environment file")
	}
	return path, cleanup, nil
}

func (s *Service) firstRun(ctx context.Context, env Environment, app Application, name, image string, hostPort int, envFile string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped", "--label", "io.serverpilot.managed=true", "--label", "io.serverpilot.application=" + app.ID, "--label", "io.serverpilot.environment=" + env.ID, "--env-file", envFile, "-p", "127.0.0.1:" + strconv.Itoa(hostPort) + ":" + strconv.Itoa(env.ContainerPort) + "/tcp", image}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(runCtx, dockerBin, args...).Output()
	if err != nil {
		return fmt.Errorf("container start failed")
	}
	containerID := strings.TrimSpace(string(out))
	if len(containerID) < 12 || len(containerID) > 64 || !isLowerHex(containerID) {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		return fmt.Errorf("container returned invalid id")
	}
	if err := deployhealth.WaitHealthy(deployhealth.Options{ContainerName: name, HostPort: hostPort, HealthURL: env.HealthPath, Timeout: 90 * time.Second}); err != nil {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		return fmt.Errorf("container health check failed")
	}
	if env.SiteEnabled {
		templateType := templates.API
		if app.Type == AppTypeNextJS {
			templateType = templates.NextJS
		}
		_, err = sites.Create(sites.CreateRequest{ContainerID: containerID, ContainerName: name, HostPort: hostPort, ContainerPort: env.ContainerPort, Domain: env.Domain, Template: templateType})
		if err != nil {
			_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
			return fmt.Errorf("site activation failed")
		}
		if env.SSLEnabled {
			if err := mapper.EnableSSL(env.Domain); err != nil {
				_ = nginx.RemoveSiteFiles(env.Domain)
				_ = sites.DeleteByConfigName(env.Domain)
				_ = nginx.ReloadNginx()
				_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
				return fmt.Errorf("SSL activation failed")
			}
		}
	}
	return nil
}

func (s *Service) replaceWithoutSite(ctx context.Context, name, image string, hostPort, containerPort int, healthPath, envFile, appID, environmentID string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	oldName := name + "-previous-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := exec.CommandContext(ctx, dockerBin, "stop", "--time", "10", "--", name).Run(); err != nil {
		return fmt.Errorf("stop current container failed")
	}
	if err := exec.CommandContext(ctx, dockerBin, "rename", name, oldName).Run(); err != nil {
		_ = exec.Command(dockerBin, "start", name).Run()
		return fmt.Errorf("stage current container failed")
	}
	restore := func() {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		_ = exec.Command(dockerBin, "rename", oldName, name).Run()
		_ = exec.Command(dockerBin, "start", name).Run()
	}
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped", "--label", "io.serverpilot.managed=true", "--label", "io.serverpilot.application=" + appID, "--label", "io.serverpilot.environment=" + environmentID, "--env-file", envFile, "-p", "127.0.0.1:" + strconv.Itoa(hostPort) + ":" + strconv.Itoa(containerPort) + "/tcp", image}
	if err := exec.CommandContext(ctx, dockerBin, args...).Run(); err != nil {
		restore()
		return fmt.Errorf("replacement container failed")
	}
	if err := deployhealth.WaitHealthy(deployhealth.Options{ContainerName: name, HostPort: hostPort, HealthURL: healthPath, Timeout: 90 * time.Second}); err != nil {
		restore()
		return fmt.Errorf("replacement health check failed")
	}
	if err := exec.CommandContext(ctx, dockerBin, "rm", "--", oldName).Run(); err != nil {
		return fmt.Errorf("remove previous container failed")
	}
	return nil
}

func nextColorName(name string) string {
	if strings.HasSuffix(name, "__green") {
		return strings.TrimSuffix(name, "__green") + "__blue"
	}
	if strings.HasSuffix(name, "__blue") {
		return strings.TrimSuffix(name, "__blue") + "__green"
	}
	return name + "__green"
}

func (s *Service) failDeployment(ctx context.Context, id, code string) error {
	if len(code) > 64 {
		code = "deployment_failed"
	}
	_, err := s.store.db.ExecContext(ctx, `UPDATE deployments SET status='failed',log_summary=?,finished_at=? WHERE id=?`, code, s.now(), id)
	if err != nil {
		return fmt.Errorf("mark deployment failed: %w", err)
	}
	return fmt.Errorf("deployment failed")
}

func (s *Service) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	if !validID(id) {
		return Deployment{}, fmt.Errorf("%w: invalid deployment", ErrInvalid)
	}
	var item Deployment
	var started, finished sql.NullTime
	err := s.store.db.QueryRowContext(ctx, `SELECT id,environment_id,artifact_id,status,trigger,actor,container_name,image_digest,log_summary,started_at,finished_at,created_at FROM deployments WHERE id=?`, id).Scan(&item.ID, &item.EnvironmentID, &item.ArtifactID, &item.Status, &item.Trigger, &item.Actor, &item.ContainerName, &item.ImageDigest, &item.LogSummary, &started, &finished, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, fmt.Errorf("%w: deployment", ErrNotFound)
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("load deployment: %w", err)
	}
	if started.Valid {
		item.StartedAt = started.Time
	}
	if finished.Valid {
		item.FinishedAt = finished.Time
	}
	return item, nil
}

func (s *Service) ListDeployments(ctx context.Context, environmentID string, limit, offset int) ([]Deployment, error) {
	if environmentID != "" && !validID(environmentID) {
		return nil, fmt.Errorf("%w: invalid environment", ErrInvalid)
	}
	limit, offset = boundedPage(limit, offset)
	query := `SELECT id,environment_id,artifact_id,status,trigger,actor,container_name,image_digest,log_summary,started_at,finished_at,created_at FROM deployments`
	args := []any{}
	if environmentID != "" {
		query += ` WHERE environment_id=?`
		args = append(args, environmentID)
	}
	query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	defer rows.Close()
	var result []Deployment
	for rows.Next() {
		var item Deployment
		var started, finished sql.NullTime
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.ArtifactID, &item.Status, &item.Trigger, &item.Actor, &item.ContainerName, &item.ImageDigest, &item.LogSummary, &started, &finished, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan deployment: %w", err)
		}
		if started.Valid {
			item.StartedAt = started.Time
		}
		if finished.Valid {
			item.FinishedAt = finished.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) queueAgentDeploy(ctx context.Context, agentID, deploymentID string) error {
	if !validID(agentID) || !validID(deploymentID) {
		return fmt.Errorf("%w: invalid agent job", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	payload := "{\"deployment_id\":\"" + deploymentID + "\"}"
	_, err = s.store.db.ExecContext(ctx, `INSERT INTO agent_jobs(id,agent_id,kind,payload,status,created_at,updated_at) VALUES(?,?, 'deploy',?,'queued',?,?)`, id, agentID, payload, s.now(), s.now())
	if err != nil {
		return fmt.Errorf("queue agent deployment: %w", err)
	}
	return nil
}

func (s *Service) StartBackground(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		cycles := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.CheckWaitingArtifacts(ctx, 50)
				s.runQueuedLocal(ctx)
				cycles++
				if cycles%30 == 0 {
					reconcileCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
					if _, err := s.GitHubConnection(reconcileCtx); err == nil {
						_ = s.SyncGitHubRepositories(reconcileCtx)
						_ = s.SyncGitHubReleases(reconcileCtx)
					}
					cancel()
				}
			}
		}
	}()
}

func (s *Service) runQueuedLocal(ctx context.Context) {
	rows, err := s.store.db.QueryContext(ctx, `SELECT d.id FROM deployments d JOIN application_environments e ON e.id=d.environment_id WHERE d.status='queued' AND e.agent_id IS NULL ORDER BY d.created_at LIMIT 10`)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		_ = s.runLocalDeployment(ctx, id)
	}
}
