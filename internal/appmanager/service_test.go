package appmanager

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	service, err := Open(filepath.Join(dir, "appmanager.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func seedRepository(t *testing.T, service *Service) Repository {
	t.Helper()
	ctx := context.Background()
	if err := service.SyncRepositories(ctx, []RepositoryInput{{GitHubID: 101, Owner: "acme", Name: "platform", DefaultBranch: "main", Language: "Go", Private: true, HTMLURL: "https://github.com/acme/platform"}}); err != nil {
		t.Fatal(err)
	}
	repositories, err := service.ListRepositories(ctx, 10, 0)
	if err != nil || len(repositories) != 1 {
		t.Fatalf("seed repository: %#v, %v", repositories, err)
	}
	return repositories[0]
}

func createTestApplication(t *testing.T, service *Service, repositoryID, name string) Application {
	t.Helper()
	application, err := service.CreateApplication(context.Background(), CreateApplicationInput{
		RepositoryID: repositoryID, Name: name, Type: AppTypeRESTAPI, Dockerfile: "Dockerfile", BuildContext: ".", ContainerPort: 8080,
		Environments: []CreateEnvironmentInput{{Name: "test", Type: EnvironmentTest}, {Name: "staging", Type: EnvironmentStaging}, {Name: "production", Type: EnvironmentProduction}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func TestApplicationCanBeUnassignedAndProjectAssignmentIsAtomic(t *testing.T) {
	service := testService(t)
	repository := seedRepository(t, service)
	application := createTestApplication(t, service, repository.ID, "orders-api")
	if application.ProjectID != nil || len(application.Environments) != 3 {
		t.Fatalf("unexpected unassigned application: %#v", application)
	}
	project, err := service.CreateProject(context.Background(), CreateProjectInput{Name: "Commerce", ApplicationIDs: []string{application.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if project.ApplicationCount != 1 {
		t.Fatalf("expected one assigned application, got %d", project.ApplicationCount)
	}
	_, err = service.CreateProject(context.Background(), CreateProjectInput{Name: "Other", ApplicationIDs: []string{application.ID}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("application must not belong to two projects: %v", err)
	}
}

func TestApplicationEnvironmentConfigurationIsCreatedAtomically(t *testing.T) {
	service := testService(t)
	repository := seedRepository(t, service)
	application, err := service.CreateApplication(context.Background(), CreateApplicationInput{
		RepositoryID: repository.ID, Name: "configured-api", Type: AppTypeRESTAPI, Dockerfile: "Dockerfile", BuildContext: ".", ContainerPort: 8080,
		Environments: []CreateEnvironmentInput{{Name: "qa", Type: EnvironmentTest, Variables: []ConfigurationInput{{Key: "LOG_LEVEL", Value: "debug"}, {Key: "API_TOKEN", Value: "private", Secret: true}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveEnvironmentVariables(context.Background(), application.Environments[0].ID)
	if err != nil || len(resolved) != 2 {
		t.Fatalf("environment configuration was not created with the application: %#v %v", resolved, err)
	}
}

func TestConfigurationPrecedenceAndSecretRedaction(t *testing.T) {
	service := testService(t)
	repository := seedRepository(t, service)
	application := createTestApplication(t, service, repository.ID, "storefront")
	project, err := service.CreateProject(context.Background(), CreateProjectInput{
		Name: "Commerce", ApplicationIDs: []string{application.ID},
		Variables: []ConfigurationInput{{Key: "API_URL", Value: "https://api.example.com"}, {Key: "LOG_LEVEL", Value: "info"}, {Key: "JWT_SECRET", Value: "project-secret", Secret: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project
	environmentID := application.Environments[1].ID
	if err := service.ReplaceConfiguration(context.Background(), "environment", environmentID, []ConfigurationInput{{Key: "API_URL", Value: "https://staging-api.example.com"}, {Key: "JWT_SECRET", Value: "environment-secret", Secret: true}}); err != nil {
		t.Fatal(err)
	}
	public, err := service.ListConfiguration(context.Background(), "environment", environmentID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range public {
		if item.Secret && item.Value != "" {
			t.Fatal("secret value leaked through configuration response")
		}
	}
	resolved, err := service.ResolveEnvironmentVariables(context.Background(), environmentID)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, item := range resolved {
		values[item.Key] = item.Value
	}
	if values["API_URL"] != "https://staging-api.example.com" || values["LOG_LEVEL"] != "info" || values["JWT_SECRET"] != "environment-secret" {
		t.Fatalf("unexpected resolved configuration: %#v", values)
	}
}

func TestReleaseWebhookIsIdempotentAndVersionIsShared(t *testing.T) {
	service := testService(t)
	ctx := context.Background()
	secret := "a-long-random-webhook-secret"
	webhookCipher, err := service.vault.encrypt(secret, "github:webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	privateCipher, err := service.vault.encrypt("unused", "github:private-key")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	connectionID, _ := newID()
	if _, err := service.store.db.ExecContext(ctx, `INSERT INTO github_connection(singleton,id,account_login,account_type,app_id,installation_id,private_key_cipher,webhook_secret_cipher,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?)`, connectionID, "acme", "Organization", 1, 2, privateCipher, webhookCipher, now, now); err != nil {
		t.Fatal(err)
	}
	repository := seedRepository(t, service)
	first := createTestApplication(t, service, repository.ID, "storefront")
	second := createTestApplication(t, service, repository.ID, "orders-api")
	payload := map[string]any{
		"action":     "published",
		"repository": map[string]any{"id": 101, "full_name": "acme/platform"},
		"release":    map[string]any{"tag_name": "v2.14.3", "target_commitish": "abc123", "name": "Release 2.14.3", "published_at": now.Format(time.RFC3339), "draft": false, "prerelease": false},
	}
	body, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	release, duplicate, err := service.HandleGitHubWebhook(ctx, signature, "delivery-1", "release", body)
	if err != nil || duplicate {
		t.Fatalf("first webhook: duplicate=%v err=%v", duplicate, err)
	}
	if release.Tag != "v2.14.3" || len(release.Artifacts) != 2 {
		t.Fatalf("unexpected release: %#v", release)
	}
	applicationIDs := map[string]bool{first.ID: false, second.ID: false}
	for _, artifact := range release.Artifacts {
		applicationIDs[artifact.ApplicationID] = true
		if artifact.Status != ArtifactWaiting || artifact.ImageReference[len(artifact.ImageReference)-len(":v2.14.3"):] != ":v2.14.3" {
			t.Fatalf("unexpected artifact: %#v", artifact)
		}
	}
	if !applicationIDs[first.ID] || !applicationIDs[second.ID] {
		t.Fatalf("one artifact per application was not created: %#v", applicationIDs)
	}
	_, duplicate, err = service.HandleGitHubWebhook(ctx, signature, "delivery-1", "release", body)
	if err != nil || !duplicate {
		t.Fatalf("repeated delivery must be idempotent: duplicate=%v err=%v", duplicate, err)
	}
	var releases, artifacts int
	_ = service.store.db.QueryRow(`SELECT COUNT(*) FROM repository_releases`).Scan(&releases)
	_ = service.store.db.QueryRow(`SELECT COUNT(*) FROM application_release_artifacts`).Scan(&artifacts)
	if releases != 1 || artifacts != 2 {
		t.Fatalf("idempotency violated: releases=%d artifacts=%d", releases, artifacts)
	}
}
