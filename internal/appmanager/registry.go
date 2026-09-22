package appmanager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	registryWorkers   = 4
	artifactWaitLimit = 30 * time.Minute
)

type artifactCheck struct {
	id        string
	image     string
	createdAt time.Time
}

func (s *Service) CheckWaitingArtifacts(ctx context.Context, limit int) error {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT id,image_reference,created_at FROM application_release_artifacts WHERE status=? ORDER BY created_at LIMIT ?`, ArtifactWaiting, limit)
	if err != nil {
		return fmt.Errorf("list waiting artifacts: %w", err)
	}
	var checks []artifactCheck
	for rows.Next() {
		var item artifactCheck
		if err := rows.Scan(&item.id, &item.image, &item.createdAt); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan waiting artifact: %w", err)
		}
		checks = append(checks, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(checks) == 0 {
		return nil
	}
	conn, err := s.GitHubConnection(ctx)
	if err != nil {
		return err
	}
	_, _, pat, err := s.githubSecrets(ctx)
	if err != nil {
		return err
	}
	type result struct {
		id, digest, code string
		status           ArtifactStatus
	}
	jobs := make(chan artifactCheck)
	results := make(chan result, len(checks))
	var wg sync.WaitGroup
	workers := registryWorkers
	if len(checks) < workers {
		workers = len(checks)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				digest, found, checkErr := checkGHCRManifestWithBackoff(ctx, conn.RegistryUsername, pat, item.image)
				res := result{id: item.id, status: ArtifactWaiting}
				switch {
				case checkErr != nil:
					res.code = "registry_unavailable"
				case found:
					res.status = ArtifactReady
					res.digest = digest
				case s.now().Sub(item.createdAt) >= artifactWaitLimit:
					res.status = ArtifactTimedOut
					res.code = "image_timeout"
				}
				results <- res
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range checks {
			select {
			case jobs <- item:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(results)
	for res := range results {
		if _, err := s.store.db.ExecContext(ctx, `UPDATE application_release_artifacts SET image_digest=?,status=?,last_checked_at=?,failure_code=?,updated_at=? WHERE id=? AND status=?`, res.digest, res.status, s.now(), res.code, s.now(), res.id, ArtifactWaiting); err != nil {
			return fmt.Errorf("update artifact status: %w", err)
		}
		if res.status == ArtifactReady {
			if err := s.queueAutoDeployments(ctx, res.id); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func checkGHCRManifestWithBackoff(ctx context.Context, username, pat, image string) (string, bool, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		digest, found, err := checkGHCRManifest(ctx, username, pat, image)
		if err == nil {
			return digest, found, nil
		}
		lastErr = err
		if attempt == 2 {
			break
		}
		delay := time.Duration(250*(1<<attempt))*time.Millisecond + registryJitter(150*time.Millisecond)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", false, ctx.Err()
		case <-timer.C:
		}
	}
	return "", false, lastErr
}

func registryJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(max))
}

func checkGHCRManifest(ctx context.Context, username, pat, image string) (string, bool, error) {
	repository, tag, ok := strings.Cut(image, ":")
	if !ok || !validImageRepository(repository) || !validReleaseTag(tag) {
		return "", false, fmt.Errorf("invalid managed image")
	}
	path := strings.TrimPrefix(repository, "ghcr.io/")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	digest, status, err := requestManifest(ctx, client, path, tag, "")
	if err != nil {
		return "", false, err
	}
	if status == http.StatusOK {
		return digest, true, nil
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if status != http.StatusUnauthorized {
		return "", false, fmt.Errorf("registry returned status %d", status)
	}
	if pat == "" {
		return "", false, nil
	}
	token, err := requestRegistryToken(ctx, client, username, pat, path)
	if err != nil {
		return "", false, err
	}
	digest, status, err = requestManifest(ctx, client, path, tag, token)
	if err != nil {
		return "", false, err
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if status != http.StatusOK {
		return "", false, fmt.Errorf("registry returned status %d", status)
	}
	return digest, true, nil
}

func requestManifest(ctx context.Context, client *http.Client, path, tag, token string) (string, int, error) {
	if strings.ContainsAny(path, "?#%\\\r\n") || !validReleaseTag(tag) {
		return "", 0, fmt.Errorf("invalid registry resource")
	}
	endpoint := "https://ghcr.io/v2/" + path + "/manifests/" + url.PathEscape(tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return "", 0, fmt.Errorf("create registry request")
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("registry request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	digest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if resp.StatusCode == http.StatusOK && (len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") || !isLowerHex(digest[7:])) {
		return "", 0, fmt.Errorf("registry returned invalid digest")
	}
	return digest, resp.StatusCode, nil
}

func requestRegistryToken(ctx context.Context, client *http.Client, username, pat, path string) (string, error) {
	if Slug(username) == "" || pat == "" || strings.ContainsAny(path, "?#%\\\r\n") {
		return "", fmt.Errorf("invalid registry credentials")
	}
	u := url.URL{Scheme: "https", Host: "ghcr.io", Path: "/token"}
	q := u.Query()
	q.Set("service", "ghcr.io")
	q.Set("scope", "repository:"+path+":pull")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create registry token request")
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+pat)))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry authentication failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry authentication returned status %d", resp.StatusCode)
	}
	var payload struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(&payload); err != nil || payload.Token == "" || len(payload.Token) > 8192 {
		return "", fmt.Errorf("registry authentication response is invalid")
	}
	return payload.Token, nil
}

func (s *Service) queueAutoDeployments(ctx context.Context, artifactID string) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin automatic deployment queue: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT e.id FROM application_environments e JOIN application_release_artifacts ara ON ara.application_id=e.application_id WHERE ara.id=? AND e.auto_deploy=1`, artifactID)
	if err != nil {
		return fmt.Errorf("load automatic deployment targets: %w", err)
	}
	var environmentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		environmentIDs = append(environmentIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, environmentID := range environmentIDs {
		id, err := newID()
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,artifact_id,status,trigger,actor,created_at) VALUES(?,?,?,'queued','auto','github',?) ON CONFLICT DO NOTHING`, id, environmentID, artifactID, s.now())
		if err != nil && !strings.Contains(strings.ToLower(err.Error()), "constraint") {
			return fmt.Errorf("queue automatic deployment: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Service) MarkArtifact(ctx context.Context, artifactID, digest string, status ArtifactStatus, failureCode string) error {
	if !validID(artifactID) {
		return fmt.Errorf("%w: invalid artifact", ErrInvalid)
	}
	if status != ArtifactReady && status != ArtifactFailed && status != ArtifactTimedOut && status != ArtifactWaiting {
		return fmt.Errorf("%w: invalid artifact status", ErrInvalid)
	}
	if digest != "" && (!strings.HasPrefix(digest, "sha256:") || len(digest) != 71 || !isLowerHex(digest[7:])) {
		return fmt.Errorf("%w: invalid digest", ErrInvalid)
	}
	if len(failureCode) > 64 {
		return fmt.Errorf("%w: invalid failure code", ErrInvalid)
	}
	res, err := s.store.db.ExecContext(ctx, `UPDATE application_release_artifacts SET image_digest=?,status=?,failure_code=?,last_checked_at=?,updated_at=? WHERE id=?`, digest, status, failureCode, s.now(), s.now(), artifactID)
	if err != nil {
		return fmt.Errorf("update artifact: %w", err)
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return fmt.Errorf("%w: artifact", ErrNotFound)
	}
	if status == ArtifactReady {
		return s.queueAutoDeployments(ctx, artifactID)
	}
	return nil
}

func (s *Service) artifactForDeployment(ctx context.Context, environmentID, artifactID string) (Environment, ApplicationReleaseArtifact, Application, error) {
	if !validID(environmentID) || !validID(artifactID) {
		return Environment{}, ApplicationReleaseArtifact{}, Application{}, fmt.Errorf("%w: invalid deployment target", ErrInvalid)
	}
	var env Environment
	var art ApplicationReleaseArtifact
	var app Application
	var agentID, projectID, artifactCurrent sql.NullString
	var hostPort sql.NullInt64
	err := s.store.db.QueryRowContext(ctx, `SELECT e.id,e.application_id,e.name,e.slug,e.type,e.agent_id,e.container_name,e.container_port,e.host_port,e.domain,e.site_enabled,e.ssl_enabled,e.health_path,e.auto_deploy,e.current_artifact_id,e.status,e.created_at,e.updated_at,a.project_id,a.repository_id,a.name,a.slug,a.type,a.image_name,ara.id,ara.release_id,ara.application_id,ara.image_reference,ara.image_digest,ara.status,ara.created_at,ara.updated_at FROM application_environments e JOIN applications a ON a.id=e.application_id JOIN application_release_artifacts ara ON ara.id=? AND ara.application_id=a.id WHERE e.id=?`, artifactID, environmentID).Scan(
		&env.ID, &env.ApplicationID, &env.Name, &env.Slug, &env.Type, &agentID, &env.ContainerName, &env.ContainerPort, &hostPort, &env.Domain, &env.SiteEnabled, &env.SSLEnabled, &env.HealthPath, &env.AutoDeploy, &artifactCurrent, &env.Status, &env.CreatedAt, &env.UpdatedAt, &projectID, &app.RepositoryID, &app.Name, &app.Slug, &app.Type, &app.ImageName, &art.ID, &art.ReleaseID, &art.ApplicationID, &art.ImageReference, &art.ImageDigest, &art.Status, &art.CreatedAt, &art.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Environment{}, ApplicationReleaseArtifact{}, Application{}, fmt.Errorf("%w: deployment target", ErrNotFound)
	}
	if err != nil {
		return Environment{}, ApplicationReleaseArtifact{}, Application{}, fmt.Errorf("load deployment target: %w", err)
	}
	if agentID.Valid {
		env.AgentID = &agentID.String
	}
	if projectID.Valid {
		app.ProjectID = &projectID.String
	}
	if hostPort.Valid {
		env.HostPort = int(hostPort.Int64)
	}
	if artifactCurrent.Valid {
		env.CurrentArtifactID = &artifactCurrent.String
	}
	return env, art, app, nil
}
