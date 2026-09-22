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

type githubReleaseRecord struct {
	Tag         string
	CommitSHA   string
	Name        string
	PublishedAt time.Time
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
	if !validDeliveryID(deliveryID) || event != "release" || len(body) == 0 || len(body) > 1<<20 {
		return RepositoryRelease{}, false, fmt.Errorf("%w: invalid webhook", ErrInvalid)
	}
	_, secret, _, err := s.githubSecrets(ctx)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if !verifyGitHubSignature(secret, body, signature) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: invalid webhook signature", ErrInvalid)
	}
	var payload githubReleasePayload
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		// GitHub adds fields over time. Decode the signed payload normally after
		// the strict envelope attempt, then validate every consumed field.
		if err := json.Unmarshal(body, &payload); err != nil {
			return RepositoryRelease{}, false, fmt.Errorf("%w: invalid webhook payload", ErrInvalid)
		}
	}
	if payload.Action != "published" || payload.Release.Draft || payload.Repository.ID < 1 || len(payload.Repository.FullName) > 201 || !validReleaseTag(payload.Release.TagName) || len(payload.Release.TargetCommitish) > 128 || len(payload.Release.Name) > 200 || payload.Release.PublishedAt.IsZero() {
		return RepositoryRelease{}, false, fmt.Errorf("%w: unsupported release payload", ErrInvalid)
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("begin webhook transaction: %w", err)
	}
	defer tx.Rollback()
	var seen int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM processed_webhooks WHERE delivery_id=?`, deliveryID).Scan(&seen); err == nil {
		return RepositoryRelease{}, true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return RepositoryRelease{}, false, fmt.Errorf("check webhook delivery: %w", err)
	}
	var repositoryID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM repositories WHERE github_id=? AND full_name=?`, payload.Repository.ID, payload.Repository.FullName).Scan(&repositoryID); errors.Is(err, sql.ErrNoRows) {
		return RepositoryRelease{}, false, fmt.Errorf("%w: repository", ErrNotFound)
	} else if err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("load webhook repository: %w", err)
	}
	record := githubReleaseRecord{Tag: payload.Release.TagName, CommitSHA: payload.Release.TargetCommitish, Name: payload.Release.Name, PublishedAt: payload.Release.PublishedAt}
	releaseID, err := s.ensureRepositoryReleaseTx(ctx, tx, repositoryID, record)
	if err != nil {
		return RepositoryRelease{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO processed_webhooks(delivery_id,event_type,processed_at) VALUES(?,?,?)`, deliveryID, event, s.now()); err != nil {
		return RepositoryRelease{}, false, fmt.Errorf("record webhook delivery: %w", err)
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

func (s *Service) ensureRepositoryReleaseTx(ctx context.Context, tx *sql.Tx, repositoryID string, record githubReleaseRecord) (string, error) {
	var releaseID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM repository_releases WHERE repository_id=? AND tag=?`, repositoryID, record.Tag).Scan(&releaseID)
	if errors.Is(err, sql.ErrNoRows) {
		releaseID, err = newID()
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO repository_releases(id,repository_id,tag,commit_sha,name,published_at,created_at) VALUES(?,?,?,?,?,?,?)`, releaseID, repositoryID, record.Tag, record.CommitSHA, record.Name, record.PublishedAt.UTC(), s.now())
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
	err := s.store.db.QueryRowContext(ctx, `SELECT id,repository_id,tag,commit_sha,name,published_at,created_at FROM repository_releases WHERE id=?`, id).Scan(&out.ID, &out.RepositoryID, &out.Tag, &out.CommitSHA, &out.Name, &out.PublishedAt, &out.CreatedAt)
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
	query := `SELECT id,repository_id,tag,commit_sha,name,published_at,created_at FROM repository_releases`
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
		if err := rows.Scan(&item.ID, &item.RepositoryID, &item.Tag, &item.CommitSHA, &item.Name, &item.PublishedAt, &item.CreatedAt); err != nil {
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
  release:
    types: [published]

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
          tags: %s:${{ github.event.release.tag_name }}
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.version=${{ github.event.release.tag_name }}
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
	rows, err := s.store.db.QueryContext(ctx, `SELECT id,owner,name FROM repositories WHERE archived=0 ORDER BY id LIMIT 5000`)
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
			_, ensureErr := s.ensureRepositoryReleaseTx(ctx, tx, repository.id, githubReleaseRecord{Tag: release.Tag, CommitSHA: release.CommitSHA, Name: release.Name, PublishedAt: release.PublishedAt})
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
