package appmanager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxGitHubResponse = 8 << 20

type githubReleasePayload struct {
	Action     string `json:"action"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Release struct {
		TagName         string    `json:"tag_name"`
		TargetCommitish string    `json:"target_commitish"`
		Name            string    `json:"name"`
		PublishedAt     time.Time `json:"published_at"`
		Draft           bool      `json:"draft"`
		Prerelease      bool      `json:"prerelease"`
	} `json:"release"`
}

type githubRepositoryPayload struct {
	Action     string `json:"action"`
	Repository struct {
		ID            int64  `json:"id"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		Language      string `json:"language"`
		Private       bool   `json:"private"`
		HTMLURL       string `json:"html_url"`
		Archived      bool   `json:"archived"`
		Owner         struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

type githubPushPayload struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Created    bool   `json:"created"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type githubReleaseRecord struct {
	Tag              string
	CommitSHA        string
	Name             string
	PublishedAt      time.Time
	TagDetected      bool
	ReleasePublished bool
}

type githubInstallation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login     string `json:"login"`
		Type      string `json:"type"`
		AvatarURL string `json:"avatar_url"`
	} `json:"account"`
}

// SetupGitHub discovers installation-owned metadata from GitHub instead of
// trusting values copied into the dashboard. Network discovery completes
// before credentials are persisted, so no database transaction spans the
// external request.
func (s *Service) SetupGitHub(ctx context.Context, in GitHubSetupInput) (GitHubSetupResult, error) {
	in.RegistryUsername = strings.TrimSpace(in.RegistryUsername)
	if in.AppID < 1 || validateGitHubPrivateKey(in.PrivateKey) != nil {
		return GitHubSetupResult{}, fmt.Errorf("%w: invalid GitHub App credentials", ErrInvalid)
	}
	jwt, err := githubAppJWT(in.AppID, in.PrivateKey, s.now())
	if err != nil {
		return GitHubSetupResult{}, fmt.Errorf("%w: invalid GitHub App credentials", ErrInvalid)
	}
	var installations []githubInstallation
	if err := githubJSON(ctx, secureGitHubClient(), http.MethodGet, "https://api.github.com/app/installations?per_page=100", jwt, nil, &installations); err != nil {
		return GitHubSetupResult{}, err
	}
	installation, err := singleGitHubInstallation(installations)
	if err != nil {
		return GitHubSetupResult{}, err
	}
	webhookSecret, err := newWebhookSecret()
	if err != nil {
		return GitHubSetupResult{}, err
	}
	connection, err := s.ConfigureGitHub(ctx, GitHubConnectionInput{
		AccountLogin:     installation.Account.Login,
		AccountType:      installation.Account.Type,
		AvatarURL:        installation.Account.AvatarURL,
		AppID:            in.AppID,
		InstallationID:   installation.ID,
		PrivateKey:       in.PrivateKey,
		WebhookSecret:    webhookSecret,
		RegistryUsername: in.RegistryUsername,
		RegistryPAT:      in.RegistryPAT,
	})
	if err != nil {
		return GitHubSetupResult{}, err
	}
	return GitHubSetupResult{Connection: connection, WebhookSecret: webhookSecret}, nil
}

func singleGitHubInstallation(installations []githubInstallation) (githubInstallation, error) {
	if len(installations) == 0 {
		return githubInstallation{}, fmt.Errorf("%w: GitHub App has no installation", ErrNotFound)
	}
	if len(installations) != 1 {
		return githubInstallation{}, fmt.Errorf("%w: GitHub App must have exactly one installation", ErrConflict)
	}
	installation := installations[0]
	installation.Account.Login = strings.TrimSpace(installation.Account.Login)
	if installation.ID < 1 || Slug(installation.Account.Login) == "" || len(installation.Account.Login) > 100 || (installation.Account.Type != "User" && installation.Account.Type != "Organization") || !validGitHubAvatarURL(installation.Account.AvatarURL) {
		return githubInstallation{}, fmt.Errorf("%w: invalid GitHub installation", ErrInvalid)
	}
	return installation, nil
}

func newWebhookSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *Service) HandleGitHubWebhook(ctx context.Context, signature, deliveryID, event string, body []byte) (RepositoryRelease, bool, error) {
	if !validDeliveryID(deliveryID) || (event != "release" && event != "repository" && event != "push") || len(body) == 0 || len(body) > 1<<20 {
		return RepositoryRelease{}, false, fmt.Errorf("%w: invalid webhook", ErrInvalid)
	}
	_, secret, _, err := s.githubSecrets(ctx)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if !verifyGitHubSignature(secret, body, signature) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: invalid webhook signature", ErrInvalid)
	}
	switch event {
	case "release":
		return s.handleGitHubReleaseWebhook(ctx, deliveryID, body)
	case "repository":
		return s.handleGitHubRepositoryWebhook(ctx, deliveryID, body)
	case "push":
		return s.handleGitHubPushWebhook(ctx, deliveryID, body)
	default:
		return RepositoryRelease{}, false, fmt.Errorf("%w: unsupported webhook", ErrInvalid)
	}
}

func (s *Service) handleGitHubReleaseWebhook(ctx context.Context, deliveryID string, body []byte) (RepositoryRelease, bool, error) {
	var payload githubReleasePayload
	if err := decodeGitHubPayload(body, &payload); err != nil {
		return RepositoryRelease{}, false, err
	}
	if payload.Action != "published" {
		duplicate, err := s.acknowledgeGitHubWebhook(ctx, deliveryID, "release")
		return RepositoryRelease{}, duplicate, err
	}
	if payload.Release.Draft || payload.Repository.ID < 1 || len(payload.Repository.FullName) > 201 || !validReleaseTag(payload.Release.TagName) || len(payload.Release.TargetCommitish) > 128 || len(payload.Release.Name) > 200 || payload.Release.PublishedAt.IsZero() {
		return RepositoryRelease{}, false, fmt.Errorf("%w: unsupported release payload", ErrInvalid)
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("begin webhook transaction: %w", err)
	}
	defer tx.Rollback()
	duplicate, err := webhookProcessedTx(ctx, tx, deliveryID)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if duplicate {
		return RepositoryRelease{}, true, nil
	}
	var repositoryID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM repositories WHERE github_id=? AND full_name=?`, payload.Repository.ID, payload.Repository.FullName).Scan(&repositoryID); errors.Is(err, sql.ErrNoRows) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: repository", ErrNotFound)
	} else if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("load webhook repository: %w", err)
	}
	record := githubReleaseRecord{Tag: payload.Release.TagName, CommitSHA: payload.Release.TargetCommitish, Name: payload.Release.Name, PublishedAt: payload.Release.PublishedAt, ReleasePublished: true}
	releaseID, err := s.ensureRepositoryReleaseTx(ctx, tx, repositoryID, record)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := s.queueReadyAutoDeploymentsForVersionTx(ctx, tx, releaseID, AutoDeployRelease); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := s.recordWebhookDeliveryTx(ctx, tx, deliveryID, "release"); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := insertAudit(ctx, tx, "github", "release.receive", "release", releaseID, payload.Release.TagName); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("commit release webhook: %w", err)
	}
	release, err := s.GetRelease(ctx, releaseID)
	return release, false, err
}

func (s *Service) handleGitHubPushWebhook(ctx context.Context, deliveryID string, body []byte) (RepositoryRelease, bool, error) {
	var payload githubPushPayload
	if err := decodeGitHubPayload(body, &payload); err != nil {
		return RepositoryRelease{}, false, err
	}
	const tagPrefix = "refs/tags/"
	tag := strings.TrimPrefix(payload.Ref, tagPrefix)
	if !payload.Created || payload.Deleted || !strings.HasPrefix(payload.Ref, tagPrefix) || !validVersionTag(tag) {
		duplicate, err := s.acknowledgeGitHubWebhook(ctx, deliveryID, "push")
		return RepositoryRelease{}, duplicate, err
	}
	if payload.Repository.ID < 1 || len(payload.Repository.FullName) > 201 || !validGitCommitSHA(payload.After) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: unsupported tag payload", ErrInvalid)
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("begin tag webhook transaction: %w", err)
	}
	defer tx.Rollback()
	duplicate, err := webhookProcessedTx(ctx, tx, deliveryID)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if duplicate {
		return RepositoryRelease{}, true, nil
	}
	var repositoryID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM repositories WHERE github_id=? AND full_name=?`, payload.Repository.ID, payload.Repository.FullName).Scan(&repositoryID); errors.Is(err, sql.ErrNoRows) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: repository", ErrNotFound)
	} else if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("load tag repository: %w", err)
	}
	releaseID, err := s.ensureRepositoryReleaseTx(ctx, tx, repositoryID, githubReleaseRecord{Tag: tag, CommitSHA: payload.After, PublishedAt: s.now(), TagDetected: true})
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := s.queueReadyAutoDeploymentsForVersionTx(ctx, tx, releaseID, AutoDeployTag); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := s.recordWebhookDeliveryTx(ctx, tx, deliveryID, "push"); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := insertAudit(ctx, tx, "github", "version.tag_detected", "release", releaseID, tag); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("commit tag webhook: %w", err)
	}
	release, err := s.GetRelease(ctx, releaseID)
	return release, false, err
}

func (s *Service) handleGitHubRepositoryWebhook(ctx context.Context, deliveryID string, body []byte) (RepositoryRelease, bool, error) {
	var payload githubRepositoryPayload
	if err := decodeGitHubPayload(body, &payload); err != nil {
		return RepositoryRelease{}, false, err
	}
	archived := payload.Repository.Archived
	switch payload.Action {
	case "created", "unarchived":
		archived = false
	case "deleted", "archived":
		archived = true
	default:
		duplicate, err := s.acknowledgeGitHubWebhook(ctx, deliveryID, "repository")
		return RepositoryRelease{}, duplicate, err
	}
	owner := strings.TrimSpace(payload.Repository.Owner.Login)
	name := strings.TrimSpace(payload.Repository.Name)
	if payload.Repository.FullName != owner+"/"+name {
		return RepositoryRelease{}, false, fmt.Errorf("%w: invalid repository payload", ErrInvalid)
	}
	in := RepositoryInput{
		GitHubID:      payload.Repository.ID,
		Owner:         owner,
		Name:          name,
		DefaultBranch: payload.Repository.DefaultBranch,
		Language:      payload.Repository.Language,
		Private:       payload.Repository.Private,
		HTMLURL:       payload.Repository.HTMLURL,
		Archived:      archived,
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("begin repository webhook transaction: %w", err)
	}
	defer tx.Rollback()
	duplicate, err := webhookProcessedTx(ctx, tx, deliveryID)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if duplicate {
		return RepositoryRelease{}, true, nil
	}
	now := s.now()
	repositoryID, err := s.upsertRepositoryTx(ctx, tx, in, now)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := s.recordWebhookDeliveryTx(ctx, tx, deliveryID, "repository"); err != nil {
		return RepositoryRelease{}, false, err
	}
	if err := insertAudit(ctx, tx, "github", "repository."+payload.Action, "repository", repositoryID, payload.Repository.FullName); err != nil {
		return RepositoryRelease{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE github_connection SET last_synced_at=?, updated_at=? WHERE singleton=1`, now, now); err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("update synchronization state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("commit repository webhook: %w", err)
	}
	return RepositoryRelease{}, false, nil
}

func decodeGitHubPayload(body []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err == nil {
		return nil
	}
	// GitHub adds fields over time. Decode the signed payload normally after
	// the strict envelope attempt, then validate every field that is consumed.
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("%w: invalid webhook payload", ErrInvalid)
	}
	return nil
}

func webhookProcessedTx(ctx context.Context, tx *sql.Tx, deliveryID string) (bool, error) {
	var seen int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM processed_webhooks WHERE delivery_id=?`, deliveryID).Scan(&seen); err == nil {
		return true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check webhook delivery: %w", err)
	}
	return false, nil
}

func (s *Service) recordWebhookDeliveryTx(ctx context.Context, tx *sql.Tx, deliveryID, event string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO processed_webhooks(delivery_id,event_type,processed_at) VALUES(?,?,?)`, deliveryID, event, s.now()); err != nil {
		return fmt.Errorf("record webhook delivery: %w", err)
	}
	return nil
}

func (s *Service) acknowledgeGitHubWebhook(ctx context.Context, deliveryID, event string) (bool, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin webhook acknowledgement: %w", err)
	}
	defer tx.Rollback()
	duplicate, err := webhookProcessedTx(ctx, tx, deliveryID)
	if err != nil || duplicate {
		return duplicate, err
	}
	if err := s.recordWebhookDeliveryTx(ctx, tx, deliveryID, event); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit webhook acknowledgement: %w", err)
	}
	return false, nil
}

func (s *Service) ensureRepositoryReleaseTx(ctx context.Context, tx *sql.Tx, repositoryID string, record githubReleaseRecord) (string, error) {
	var releaseID string
	var existingCommit string
	var tagDetected, releasePublished bool
	err := tx.QueryRowContext(ctx, `SELECT id,commit_sha,tag_detected,release_published FROM repository_releases WHERE repository_id=? AND tag=?`, repositoryID, record.Tag).Scan(&releaseID, &existingCommit, &tagDetected, &releasePublished)
	if errors.Is(err, sql.ErrNoRows) {
		releaseID, err = newID()
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO repository_releases(id,repository_id,tag,commit_sha,name,tag_detected,release_published,published_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, releaseID, repositoryID, record.Tag, record.CommitSHA, record.Name, record.TagDetected, record.ReleasePublished, record.PublishedAt.UTC(), s.now())
	} else if err == nil {
		if record.TagDetected && tagDetected && existingCommit != record.CommitSHA {
			return "", fmt.Errorf("%w: version tag moved", ErrConflict)
		}
		if record.TagDetected {
			publishedAt := record.PublishedAt.UTC()
			if releasePublished {
				_, err = tx.ExecContext(ctx, `UPDATE repository_releases SET commit_sha=?,tag_detected=1 WHERE id=?`, record.CommitSHA, releaseID)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE repository_releases SET commit_sha=?,tag_detected=1,published_at=? WHERE id=?`, record.CommitSHA, publishedAt, releaseID)
			}
		}
		if err == nil && record.ReleasePublished {
			commitSHA := record.CommitSHA
			if tagDetected || record.TagDetected {
				commitSHA = existingCommit
				if record.TagDetected {
					commitSHA = record.CommitSHA
				}
			}
			_, err = tx.ExecContext(ctx, `UPDATE repository_releases SET commit_sha=?,name=?,release_published=1,published_at=? WHERE id=?`, commitSHA, record.Name, record.PublishedAt.UTC(), releaseID)
		}
	}
	if err != nil {
		return "", fmt.Errorf("save repository release: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,image_name FROM applications WHERE repository_id=? ORDER BY id`, repositoryID)
	if err != nil {
		return "", fmt.Errorf("load release applications: %w", err)
	}
	type releaseApp struct{ id, image string }
	var apps []releaseApp
	for rows.Next() {
		var app releaseApp
		if err := rows.Scan(&app.id, &app.image); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("scan release application: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Close(); err != nil {
		return "", fmt.Errorf("close release applications: %w", err)
	}
	for _, app := range apps {
		artifactID, err := newID()
		if err != nil {
			return "", err
		}
		imageRef, err := ImageReference(app.image, record.Tag, "")
		if err != nil {
			return "", err
		}
		now := s.now()
		if _, err = tx.ExecContext(ctx, `INSERT INTO application_release_artifacts(id,release_id,application_id,image_reference,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(release_id,application_id) DO NOTHING`, artifactID, releaseID, app.id, imageRef, ArtifactWaiting, now, now); err != nil {
			return "", fmt.Errorf("save release artifact: %w", err)
		}
	}
	return releaseID, nil
}

func verifyGitHubSignature(secret string, body []byte, header string) bool {
	if !strings.HasPrefix(header, "sha256=") || len(header) != 71 {
		return false
	}
	received, err := hex.DecodeString(header[7:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return len(received) == len(expected) && subtle.ConstantTimeCompare(received, expected) == 1
}

func validDeliveryID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) GetRelease(ctx context.Context, id string) (RepositoryRelease, error) {
	if !validID(id) {
		return RepositoryRelease{}, fmt.Errorf("%w: invalid release", ErrInvalid)
	}
	var out RepositoryRelease
	err := s.store.db.QueryRowContext(ctx, `SELECT id,repository_id,tag,commit_sha,name,tag_detected,release_published,published_at,created_at FROM repository_releases WHERE id=?`, id).Scan(&out.ID, &out.RepositoryID, &out.Tag, &out.CommitSHA, &out.Name, &out.TagDetected, &out.ReleasePublished, &out.PublishedAt, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RepositoryRelease{}, fmt.Errorf("%w: release", ErrNotFound)
	}
	if err != nil {
		return RepositoryRelease{}, fmt.Errorf("load release: %w", err)
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT ara.id,ara.release_id,ara.application_id,a.name,ara.image_reference,ara.image_digest,ara.status,ara.last_checked_at,ara.failure_code,ara.created_at,ara.updated_at FROM application_release_artifacts ara JOIN applications a ON a.id=ara.application_id WHERE ara.release_id=? ORDER BY a.name`, id)
	if err != nil {
		return RepositoryRelease{}, fmt.Errorf("load release artifacts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ApplicationReleaseArtifact
		var checked sql.NullTime
		if err := rows.Scan(&item.ID, &item.ReleaseID, &item.ApplicationID, &item.Application, &item.ImageReference, &item.ImageDigest, &item.Status, &checked, &item.FailureCode, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return RepositoryRelease{}, fmt.Errorf("scan release artifact: %w", err)
		}
		if checked.Valid {
			item.LastCheckedAt = checked.Time
		}
		out.Artifacts = append(out.Artifacts, item)
	}
	return out, rows.Err()
}

func (s *Service) ListReleases(ctx context.Context, repositoryID string, limit, offset int) ([]RepositoryRelease, error) {
	if repositoryID != "" && !validID(repositoryID) {
		return nil, fmt.Errorf("%w: invalid repository", ErrInvalid)
	}
	limit, offset = boundedPage(limit, offset)
	query := `SELECT id,repository_id,tag,commit_sha,name,tag_detected,release_published,published_at,created_at FROM repository_releases`
	args := []any{}
	if repositoryID != "" {
		query += ` WHERE repository_id=?`
		args = append(args, repositoryID)
	}
	query += ` ORDER BY published_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	defer rows.Close()
	var result []RepositoryRelease
	for rows.Next() {
		var item RepositoryRelease
		if err := rows.Scan(&item.ID, &item.RepositoryID, &item.Tag, &item.CommitSHA, &item.Name, &item.TagDetected, &item.ReleasePublished, &item.PublishedAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan release: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ListApplicationArtifacts(ctx context.Context, applicationID string, limit, offset int) ([]ApplicationReleaseArtifact, error) {
	if !validID(applicationID) {
		return nil, fmt.Errorf("%w: invalid application", ErrInvalid)
	}
	limit, offset = boundedPage(limit, offset)
	rows, err := s.store.db.QueryContext(ctx, `SELECT ara.id,ara.release_id,ara.application_id,a.name,ara.image_reference,ara.image_digest,ara.status,ara.last_checked_at,ara.failure_code,ara.created_at,ara.updated_at FROM application_release_artifacts ara JOIN applications a ON a.id=ara.application_id JOIN repository_releases rr ON rr.id=ara.release_id WHERE ara.application_id=? ORDER BY rr.published_at DESC LIMIT ? OFFSET ?`, applicationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list application artifacts: %w", err)
	}
	defer rows.Close()
	var result []ApplicationReleaseArtifact
	for rows.Next() {
		var item ApplicationReleaseArtifact
		var checked sql.NullTime
		if err := rows.Scan(&item.ID, &item.ReleaseID, &item.ApplicationID, &item.Application, &item.ImageReference, &item.ImageDigest, &item.Status, &checked, &item.FailureCode, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan application artifact: %w", err)
		}
		if checked.Valid {
			item.LastCheckedAt = checked.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) GeneratedWorkflow(ctx context.Context, applicationID string) (string, error) {
	app, err := s.GetApplication(ctx, applicationID)
	if err != nil {
		return "", err
	}
	workflow := fmt.Sprintf(`name: ServerPilot image

on:
  push:
    tags:
      - "v*"

permissions:
  contents: read
  packages: write

jobs:
  build-%s:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: %s
          file: %s
          push: true
          tags: %s:${{ github.ref_name }}
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.version=${{ github.ref_name }}
            io.serverpilot.managed=true
            io.serverpilot.application=%s
`, app.Slug, app.BuildContext, app.Dockerfile, app.ImageName, app.ID)
	return workflow, nil
}

func (s *Service) SyncGitHubRepositories(ctx context.Context) error {
	client, token, err := s.githubInstallationAccess(ctx)
	if err != nil {
		return err
	}
	var all []RepositoryInput
	for page := 1; page <= 50; page++ {
		endpoint := "https://api.github.com/installation/repositories?per_page=100&page=" + strconv.Itoa(page)
		var response struct {
			Repositories []struct {
				ID            int64  `json:"id"`
				Name          string `json:"name"`
				FullName      string `json:"full_name"`
				Private       bool   `json:"private"`
				HTMLURL       string `json:"html_url"`
				DefaultBranch string `json:"default_branch"`
				Language      string `json:"language"`
				Archived      bool   `json:"archived"`
				Owner         struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		if err := githubJSON(ctx, client, http.MethodGet, endpoint, token, nil, &response); err != nil {
			return err
		}
		for _, repo := range response.Repositories {
			all = append(all, RepositoryInput{GitHubID: repo.ID, Owner: repo.Owner.Login, Name: repo.Name, DefaultBranch: repo.DefaultBranch, Language: repo.Language, Private: repo.Private, HTMLURL: repo.HTMLURL, Archived: repo.Archived})
		}
		if len(response.Repositories) < 100 {
			break
		}
	}
	return s.SyncRepositories(ctx, all)
}

// SyncGitHubReleases reconciles recent published releases so missed webhook
// deliveries do not leave the local control plane permanently stale.
func (s *Service) SyncGitHubReleases(ctx context.Context) error {
	client, token, err := s.githubInstallationAccess(ctx)
	if err != nil {
		return err
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT DISTINCT r.id,r.owner,r.name FROM repositories r JOIN applications a ON a.repository_id=r.id WHERE r.archived=0 ORDER BY r.id LIMIT 1000`)
	if err != nil {
		return fmt.Errorf("list repositories for release reconciliation: %w", err)
	}
	type repositoryRef struct{ id, owner, name string }
	var repositories []repositoryRef
	for rows.Next() {
		var repository repositoryRef
		if err := rows.Scan(&repository.id, &repository.owner, &repository.name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan release repository: %w", err)
		}
		repositories = append(repositories, repository)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, repository := range repositories {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		endpoint := "https://api.github.com/repos/" + url.PathEscape(repository.owner) + "/" + url.PathEscape(repository.name) + "/releases?per_page=100&page=1"
		var releases []struct {
			Tag         string    `json:"tag_name"`
			CommitSHA   string    `json:"target_commitish"`
			Name        string    `json:"name"`
			PublishedAt time.Time `json:"published_at"`
			Draft       bool      `json:"draft"`
		}
		if err := githubJSON(ctx, client, http.MethodGet, endpoint, token, nil, &releases); err != nil {
			return err
		}
		for _, release := range releases {
			if release.Draft || release.PublishedAt.IsZero() || !validReleaseTag(release.Tag) || len(release.CommitSHA) > 128 || len(release.Name) > 200 {
				continue
			}
			tx, err := s.store.db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("begin release reconciliation: %w", err)
			}
			releaseID, ensureErr := s.ensureRepositoryReleaseTx(ctx, tx, repository.id, githubReleaseRecord{Tag: release.Tag, CommitSHA: release.CommitSHA, Name: release.Name, PublishedAt: release.PublishedAt, ReleasePublished: true})
			if ensureErr == nil {
				ensureErr = s.queueReadyAutoDeploymentsForVersionTx(ctx, tx, releaseID, AutoDeployRelease)
			}
			if ensureErr == nil {
				ensureErr = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			if ensureErr != nil {
				return ensureErr
			}
		}
	}
	return nil
}

// SyncGitHubTags reconciles recent version tags for repositories that are
// actually linked to applications. This recovers from missed push webhooks
// without scanning repositories that cannot produce a deployment.
func (s *Service) SyncGitHubTags(ctx context.Context) error {
	client, token, err := s.githubInstallationAccess(ctx)
	if err != nil {
		return err
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT DISTINCT r.id,r.owner,r.name FROM repositories r JOIN applications a ON a.repository_id=r.id WHERE r.archived=0 ORDER BY r.id LIMIT 1000`)
	if err != nil {
		return fmt.Errorf("list repositories for tag reconciliation: %w", err)
	}
	type repositoryRef struct{ id, owner, name string }
	var repositories []repositoryRef
	for rows.Next() {
		var repository repositoryRef
		if err := rows.Scan(&repository.id, &repository.owner, &repository.name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan tag repository: %w", err)
		}
		repositories = append(repositories, repository)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, repository := range repositories {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		endpoint := "https://api.github.com/repos/" + url.PathEscape(repository.owner) + "/" + url.PathEscape(repository.name) + "/tags?per_page=100&page=1"
		var tags []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		if err := githubJSON(ctx, client, http.MethodGet, endpoint, token, nil, &tags); err != nil {
			return err
		}
		for _, tag := range tags {
			if !validVersionTag(tag.Name) || !validGitCommitSHA(tag.Commit.SHA) {
				continue
			}
			tx, err := s.store.db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("begin tag reconciliation: %w", err)
			}
			releaseID, ensureErr := s.ensureRepositoryReleaseTx(ctx, tx, repository.id, githubReleaseRecord{Tag: tag.Name, CommitSHA: tag.Commit.SHA, PublishedAt: s.now(), TagDetected: true})
			if ensureErr == nil {
				ensureErr = s.queueReadyAutoDeploymentsForVersionTx(ctx, tx, releaseID, AutoDeployTag)
			}
			if ensureErr == nil {
				ensureErr = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			if ensureErr != nil {
				return ensureErr
			}
		}
	}
	return nil
}

func (s *Service) githubInstallationAccess(ctx context.Context) (*http.Client, string, error) {
	conn, err := s.GitHubConnection(ctx)
	if err != nil {
		return nil, "", err
	}
	privateKey, _, _, err := s.githubSecrets(ctx)
	if err != nil {
		return nil, "", err
	}
	jwt, err := githubAppJWT(conn.AppID, privateKey, s.now())
	if err != nil {
		return nil, "", err
	}
	client := secureGitHubClient()
	tokenURL := "https://api.github.com/app/installations/" + strconv.FormatInt(conn.InstallationID, 10) + "/access_tokens"
	var tokenResponse struct {
		Token string `json:"token"`
	}
	if err := githubJSON(ctx, client, http.MethodPost, tokenURL, jwt, nil, &tokenResponse); err != nil {
		return nil, "", err
	}
	if tokenResponse.Token == "" || len(tokenResponse.Token) > 8192 {
		return nil, "", fmt.Errorf("GitHub did not return a valid installation token")
	}
	return client, tokenResponse.Token, nil
}

func githubAppJWT(appID int64, privatePEM string, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return "", fmt.Errorf("invalid GitHub private key")
	}
	var key *rsa.PrivateKey
	var err error
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	}
	if err != nil || key == nil {
		return "", fmt.Errorf("invalid GitHub private key")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any{"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(8 * time.Minute).Unix(), "iss": strconv.FormatInt(appID, 10)})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub token: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func secureGitHubClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func githubJSON(ctx context.Context, client *http.Client, method, endpoint, token string, body any, out any) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "api.github.com" || u.User != nil {
		return fmt.Errorf("invalid GitHub endpoint")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode GitHub request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("create GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub request returned status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxGitHubResponse+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read GitHub response")
	}
	if len(raw) > maxGitHubResponse {
		return fmt.Errorf("GitHub response too large")
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("invalid GitHub response")
		}
	}
	return nil
}
