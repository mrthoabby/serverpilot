package appmanager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Service) SyncRepositories(ctx context.Context, inputs []RepositoryInput) error {
	if len(inputs) > 5000 {
		return fmt.Errorf("%w: too many repositories", ErrInvalid)
	}
	now := s.now()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repository sync: %w", err)
	}
	defer tx.Rollback()
	for _, in := range inputs {
		if _, err := s.upsertRepositoryTx(ctx, tx, in, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE github_connection SET last_synced_at=?, updated_at=? WHERE singleton=1`, now, now); err != nil {
		return fmt.Errorf("update synchronization state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repository sync: %w", err)
	}
	return nil
}

func (s *Service) upsertRepositoryTx(ctx context.Context, tx *sql.Tx, in RepositoryInput, now time.Time) (string, error) {
	in.Owner = strings.TrimSpace(in.Owner)
	in.Name = strings.TrimSpace(in.Name)
	if in.GitHubID < 1 || Slug(in.Owner) == "" || Slug(in.Name) == "" || len(in.Owner) > 100 || len(in.Name) > 100 || len(in.DefaultBranch) > 255 || len(in.Language) > 100 || !validRepositoryURL(in.HTMLURL, in.Owner, in.Name) {
		return "", fmt.Errorf("%w: invalid repository", ErrInvalid)
	}
	id, err := repositoryIDByGitHub(ctx, tx, in.GitHubID)
	if err != nil {
		return "", err
	}
	if id == "" {
		id, err = newID()
		if err != nil {
			return "", err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO repositories(id,github_id,owner,name,full_name,default_branch,language,private,html_url,archived,last_synced_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(github_id) DO UPDATE SET owner=excluded.owner,name=excluded.name,full_name=excluded.full_name,default_branch=excluded.default_branch,language=excluded.language,private=excluded.private,html_url=excluded.html_url,archived=excluded.archived,last_synced_at=excluded.last_synced_at,updated_at=excluded.updated_at`,
		id, in.GitHubID, in.Owner, in.Name, in.Owner+"/"+in.Name, in.DefaultBranch, in.Language, in.Private, in.HTMLURL, in.Archived, now, now, now)
	if err != nil {
		return "", fmt.Errorf("save repository: %w", err)
	}
	return id, nil
}

func repositoryIDByGitHub(ctx context.Context, tx *sql.Tx, githubID int64) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM repositories WHERE github_id=?`, githubID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find repository: %w", err)
	}
	return id, nil
}

func validRepositoryURL(raw, owner, name string) bool {
	want := "https://github.com/" + owner + "/" + name
	return raw == want || raw == want+"/"
}

func (s *Service) ListRepositories(ctx context.Context, limit, offset int) ([]Repository, error) {
	limit, offset = boundedPage(limit, offset)
	rows, err := s.store.db.QueryContext(ctx, `SELECT r.id,r.github_id,r.owner,r.name,r.full_name,r.default_branch,r.language,r.private,r.html_url,r.archived,r.last_synced_at,COUNT(a.id)
FROM repositories r LEFT JOIN applications a ON a.repository_id=r.id GROUP BY r.id ORDER BY r.full_name LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()
	var result []Repository
	for rows.Next() {
		var item Repository
		if err := rows.Scan(&item.ID, &item.GitHubID, &item.Owner, &item.Name, &item.FullName, &item.DefaultBranch, &item.Language, &item.Private, &item.HTMLURL, &item.Archived, &item.LastSyncedAt, &item.AppCount); err != nil {
			return nil, fmt.Errorf("scan repository: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) CreateApplication(ctx context.Context, in CreateApplicationInput) (Application, error) {
	if err := ValidateCreateApplication(in); err != nil {
		return Application{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	slug := Slug(in.Name)
	now := s.now()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Application{}, fmt.Errorf("begin application creation: %w", err)
	}
	defer tx.Rollback()
	var owner, repository string
	if err := tx.QueryRowContext(ctx, `SELECT owner,name FROM repositories WHERE id=? AND archived=0`, in.RepositoryID).Scan(&owner, &repository); errors.Is(err, sql.ErrNoRows) {
		return Application{}, fmt.Errorf("%w: repository", ErrNotFound)
	} else if err != nil {
		return Application{}, fmt.Errorf("load repository: %w", err)
	}
	if in.ProjectID != nil {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM projects WHERE id=?`, *in.ProjectID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return Application{}, fmt.Errorf("%w: project", ErrNotFound)
		} else if err != nil {
			return Application{}, fmt.Errorf("load project: %w", err)
		}
	}
	id, err := newID()
	if err != nil {
		return Application{}, err
	}
	imageName, err := ImageRepository(owner, repository, in.Name)
	if err != nil {
		return Application{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO applications(id,project_id,repository_id,name,slug,description,type,dockerfile,build_context,container_port,image_name,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, in.ProjectID, in.RepositoryID, in.Name, slug, strings.TrimSpace(in.Description), in.Type, in.Dockerfile, in.BuildContext, in.ContainerPort, imageName, now, now)
	if err != nil {
		return Application{}, mapConstraintError(err, "application already exists")
	}
	for _, environment := range in.Environments {
		envID, err := newID()
		if err != nil {
			return Application{}, err
		}
		envSlug := Slug(environment.Name)
		containerName := managedContainerName(slug, envSlug, id)
		autoDeploy := environment.AutoDeployMode != AutoDeployManual
		autoDeploySource := environment.AutoDeployMode
		if autoDeploySource == AutoDeployManual {
			autoDeploySource = AutoDeployRelease
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO application_environments(id,application_id,name,slug,type,agent_id,container_name,container_port,domain,site_enabled,ssl_enabled,health_path,auto_deploy,auto_deploy_source,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'idle',?,?)`,
			envID, id, strings.TrimSpace(environment.Name), envSlug, environment.Type, environment.AgentID, containerName, in.ContainerPort, strings.ToLower(environment.Domain), environment.SiteEnabled, environment.SSLEnabled, environment.HealthPath, autoDeploy, autoDeploySource, now, now)
		if err != nil {
			return Application{}, mapConstraintError(err, "environment already exists")
		}
		if err := s.replaceConfigurationTx(ctx, tx, "environment", envID, environment.Variables); err != nil {
			return Application{}, err
		}
	}
	if err := insertAudit(ctx, tx, "system", "application.create", "application", id, ""); err != nil {
		return Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return Application{}, fmt.Errorf("commit application creation: %w", err)
	}
	return s.GetApplication(ctx, id)
}

func managedContainerName(appSlug, envSlug, appID string) string {
	base := "sp-" + appSlug + "-" + envSlug
	if len(base) > 108 {
		base = strings.TrimRight(base[:108], "-")
	}
	return base + "-" + appID[:8]
}

func (s *Service) UpdateEnvironmentDeployPolicy(ctx context.Context, in UpdateEnvironmentDeployPolicyInput) error {
	if !validID(in.EnvironmentID) || in.Mode != AutoDeployManual && in.Mode != AutoDeployTag && in.Mode != AutoDeployRelease {
		return fmt.Errorf("%w: invalid deployment policy", ErrInvalid)
	}
	autoDeploy := in.Mode != AutoDeployManual
	source := in.Mode
	if source == AutoDeployManual {
		source = AutoDeployRelease
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deployment policy update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE application_environments SET auto_deploy=?,auto_deploy_source=?,updated_at=? WHERE id=?`, autoDeploy, source, s.now(), in.EnvironmentID)
	if err != nil {
		return fmt.Errorf("update deployment policy: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("confirm deployment policy update: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("%w: environment", ErrNotFound)
	}
	if err := insertAudit(ctx, tx, "dashboard", "environment.deploy_policy", "environment", in.EnvironmentID, string(in.Mode)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deployment policy update: %w", err)
	}
	return nil
}

func (s *Service) ListApplications(ctx context.Context, assignment string, limit, offset int) ([]Application, error) {
	limit, offset = boundedPage(limit, offset)
	condition := "1=1"
	switch assignment {
	case "", "all":
	case "assigned":
		condition = "a.project_id IS NOT NULL"
	case "unassigned":
		condition = "a.project_id IS NULL"
	default:
		return nil, fmt.Errorf("%w: invalid assignment filter", ErrInvalid)
	}
	query := `SELECT a.id,a.project_id,COALESCE(p.name,''),a.repository_id,r.full_name,a.name,a.slug,a.description,a.type,a.dockerfile,a.build_context,a.container_port,a.image_name,a.created_at,a.updated_at
FROM applications a JOIN repositories r ON r.id=a.repository_id LEFT JOIN projects p ON p.id=a.project_id WHERE ` + condition + ` ORDER BY a.name LIMIT ? OFFSET ?`
	rows, err := s.store.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()
	var result []Application
	for rows.Next() {
		item, err := scanApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	if err := s.attachEnvironments(ctx, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) GetApplication(ctx context.Context, id string) (Application, error) {
	if !validID(id) {
		return Application{}, fmt.Errorf("%w: invalid application", ErrInvalid)
	}
	row := s.store.db.QueryRowContext(ctx, `SELECT a.id,a.project_id,COALESCE(p.name,''),a.repository_id,r.full_name,a.name,a.slug,a.description,a.type,a.dockerfile,a.build_context,a.container_port,a.image_name,a.created_at,a.updated_at FROM applications a JOIN repositories r ON r.id=a.repository_id LEFT JOIN projects p ON p.id=a.project_id WHERE a.id=?`, id)
	item, err := scanApplication(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, fmt.Errorf("%w: application", ErrNotFound)
	}
	if err != nil {
		return Application{}, err
	}
	items := []Application{item}
	if err := s.attachEnvironments(ctx, items); err != nil {
		return Application{}, err
	}
	return items[0], nil
}

type scanner interface{ Scan(...any) error }

func scanApplication(row scanner) (Application, error) {
	var item Application
	var projectID sql.NullString
	if err := row.Scan(&item.ID, &projectID, &item.ProjectName, &item.RepositoryID, &item.Repository, &item.Name, &item.Slug, &item.Description, &item.Type, &item.Dockerfile, &item.BuildContext, &item.ContainerPort, &item.ImageName, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return Application{}, err
	}
	if projectID.Valid {
		item.ProjectID = &projectID.String
	}
	return item, nil
}

func (s *Service) attachEnvironments(ctx context.Context, apps []Application) error {
	byID := make(map[string]*Application, len(apps))
	args := make([]any, 0, len(apps))
	placeholders := make([]string, 0, len(apps))
	for i := range apps {
		byID[apps[i].ID] = &apps[i]
		args = append(args, apps[i].ID)
		placeholders = append(placeholders, "?")
	}
	if len(byID) == 0 {
		return nil
	}
	query := `SELECT e.id,e.application_id,e.name,e.slug,e.type,e.agent_id,e.container_name,e.container_port,e.host_port,e.domain,e.site_enabled,e.ssl_enabled,e.health_path,CASE WHEN e.auto_deploy=0 THEN 'manual' ELSE e.auto_deploy_source END,e.current_artifact_id,COALESCE(rr.tag,''),e.status,e.last_deployment_at,e.created_at,e.updated_at FROM application_environments e LEFT JOIN application_release_artifacts ara ON ara.id=e.current_artifact_id LEFT JOIN repository_releases rr ON rr.id=ara.release_id WHERE e.application_id IN (` + strings.Join(placeholders, ",") + `) ORDER BY e.application_id,CASE e.type WHEN 'production' THEN 1 WHEN 'staging' THEN 2 ELSE 3 END,e.name`
	rows, err := s.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("list environments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Environment
		var agentID, artifactID sql.NullString
		var hostPort sql.NullInt64
		var deployedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.Name, &item.Slug, &item.Type, &agentID, &item.ContainerName, &item.ContainerPort, &hostPort, &item.Domain, &item.SiteEnabled, &item.SSLEnabled, &item.HealthPath, &item.AutoDeployMode, &artifactID, &item.CurrentVersion, &item.Status, &deployedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return fmt.Errorf("scan environment: %w", err)
		}
		if agentID.Valid {
			item.AgentID = &agentID.String
		}
		if artifactID.Valid {
			item.CurrentArtifactID = &artifactID.String
		}
		if hostPort.Valid {
			item.HostPort = int(hostPort.Int64)
		}
		if deployedAt.Valid {
			item.LastDeploymentAt = deployedAt.Time
		}
		if app := byID[item.ApplicationID]; app != nil {
			app.Environments = append(app.Environments, item)
		}
	}
	return rows.Err()
}

func (s *Service) CreateProject(ctx context.Context, in CreateProjectInput) (Project, error) {
	if err := ValidateCreateProject(in); err != nil {
		return Project{}, err
	}
	now := s.now()
	id, err := newID()
	if err != nil {
		return Project{}, err
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, fmt.Errorf("begin project creation: %w", err)
	}
	defer tx.Rollback()
	for _, appID := range in.ApplicationIDs {
		var projectID sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT project_id FROM applications WHERE id=?`, appID).Scan(&projectID); errors.Is(err, sql.ErrNoRows) {
			return Project{}, fmt.Errorf("%w: application", ErrNotFound)
		} else if err != nil {
			return Project{}, fmt.Errorf("load application: %w", err)
		}
		if projectID.Valid {
			return Project{}, fmt.Errorf("%w: application already belongs to a project", ErrConflict)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO projects(id,name,slug,description,created_at,updated_at) VALUES(?,?,?,?,?,?)`, id, strings.TrimSpace(in.Name), Slug(in.Name), strings.TrimSpace(in.Description), now, now)
	if err != nil {
		return Project{}, mapConstraintError(err, "project already exists")
	}
	for _, appID := range in.ApplicationIDs {
		res, err := tx.ExecContext(ctx, `UPDATE applications SET project_id=?,updated_at=? WHERE id=? AND project_id IS NULL`, id, now, appID)
		if err != nil {
			return Project{}, fmt.Errorf("assign application: %w", err)
		}
		count, _ := res.RowsAffected()
		if count != 1 {
			return Project{}, fmt.Errorf("%w: application assignment changed", ErrConflict)
		}
	}
	if err := s.replaceConfigurationTx(ctx, tx, "project", id, in.Variables); err != nil {
		return Project{}, err
	}
	if err := insertAudit(ctx, tx, "system", "project.create", "project", id, ""); err != nil {
		return Project{}, err
	}
	if err := tx.Commit(); err != nil {
		return Project{}, fmt.Errorf("commit project creation: %w", err)
	}
	return s.GetProject(ctx, id)
}

func (s *Service) ListProjects(ctx context.Context, limit, offset int) ([]Project, error) {
	limit, offset = boundedPage(limit, offset)
	rows, err := s.store.db.QueryContext(ctx, `SELECT p.id,p.name,p.slug,p.description,COUNT(a.id),p.created_at,p.updated_at FROM projects p JOIN applications a ON a.project_id=p.id GROUP BY p.id ORDER BY p.name LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()
	var result []Project
	for rows.Next() {
		var item Project
		if err := rows.Scan(&item.ID, &item.Name, &item.Slug, &item.Description, &item.ApplicationCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) GetProject(ctx context.Context, id string) (Project, error) {
	if !validID(id) {
		return Project{}, fmt.Errorf("%w: invalid project", ErrInvalid)
	}
	var item Project
	err := s.store.db.QueryRowContext(ctx, `SELECT p.id,p.name,p.slug,p.description,COUNT(a.id),p.created_at,p.updated_at FROM projects p JOIN applications a ON a.project_id=p.id WHERE p.id=? GROUP BY p.id`, id).Scan(&item.ID, &item.Name, &item.Slug, &item.Description, &item.ApplicationCount, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, fmt.Errorf("%w: project", ErrNotFound)
	}
	if err != nil {
		return Project{}, fmt.Errorf("load project: %w", err)
	}
	return item, nil
}

func boundedPage(limit, offset int) (int, int) {
	if limit < 1 || limit > maxPageSize {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func mapConstraintError(err error, message string) error {
	if strings.Contains(strings.ToLower(err.Error()), "constraint") {
		return fmt.Errorf("%w: %s", ErrConflict, message)
	}
	return err
}

func insertAudit(ctx context.Context, tx *sql.Tx, actor, action, resourceType, resourceID, detail string) error {
	id, err := newID()
	if err != nil {
		return err
	}
	if len(detail) > 500 {
		detail = detail[:500]
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,resource_type,resource_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`, id, actor, action, resourceType, resourceID, detail, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}
