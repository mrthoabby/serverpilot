package appmanager

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
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
		Environments: []CreateEnvironmentInput{{Name: "test", Type: EnvironmentTest, AutoDeployMode: AutoDeployManual}, {Name: "staging", Type: EnvironmentStaging, AutoDeployMode: AutoDeployManual}, {Name: "production", Type: EnvironmentProduction, AutoDeployMode: AutoDeployManual}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func configureTestWebhook(t *testing.T, service *Service, secret string) {
	t.Helper()
	webhookCipher, err := service.vault.encrypt(secret, "github:webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	privateCipher, err := service.vault.encrypt("unused", "github:private-key")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	connectionID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.store.db.ExecContext(context.Background(), `INSERT INTO github_connection(singleton,id,account_login,account_type,app_id,installation_id,private_key_cipher,webhook_secret_cipher,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?)`, connectionID, "acme", "Organization", 1, 2, privateCipher, webhookCipher, now, now); err != nil {
		t.Fatal(err)
	}
}

func sendTestWebhook(t *testing.T, service *Service, secret, deliveryID, event string, payload any) (RepositoryRelease, bool, error) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return service.HandleGitHubWebhook(context.Background(), signature, deliveryID, event, body)
}

func repositoryWebhookPayload(action string) map[string]any {
	return map[string]any{
		"action": action,
		"repository": map[string]any{
			"id":             202,
			"name":           "events",
			"full_name":      "acme/events",
			"default_branch": "main",
			"language":       "Go",
			"private":        true,
			"html_url":       "https://github.com/acme/events",
			"archived":       action == "archived",
			"owner":          map[string]any{"login": "acme"},
		},
	}
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
		Environments: []CreateEnvironmentInput{{Name: "qa", Type: EnvironmentTest, AutoDeployMode: AutoDeployManual, Variables: []ConfigurationInput{{Key: "LOG_LEVEL", Value: "debug"}, {Key: "API_TOKEN", Value: "private", Secret: true}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveEnvironmentVariables(context.Background(), application.Environments[0].ID)
	if err != nil || len(resolved) != 2 {
		t.Fatalf("environment configuration was not created with the application: %#v %v", resolved, err)
	}
}

func TestEnvironmentDeployPolicyCanBeChanged(t *testing.T) {
	service := testService(t)
	repository := seedRepository(t, service)
	application := createTestApplication(t, service, repository.ID, "policy-api")
	environmentID := application.Environments[0].ID
	if err := service.UpdateEnvironmentDeployPolicy(context.Background(), UpdateEnvironmentDeployPolicyInput{EnvironmentID: environmentID, Mode: AutoDeployTag}); err != nil {
		t.Fatal(err)
	}
	updated, err := service.GetApplication(context.Background(), application.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, environment := range updated.Environments {
		if environment.ID == environmentID {
			found = true
			if environment.AutoDeployMode != AutoDeployTag {
				t.Fatalf("unexpected deployment policy: %s", environment.AutoDeployMode)
			}
		}
	}
	if !found {
		t.Fatal("updated environment was not returned")
	}
	workflow, err := service.GeneratedWorkflow(context.Background(), application.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(workflow, "push:\n    tags:\n      - \"v*\"") || !strings.Contains(workflow, "${{ github.ref_name }}") || strings.Contains(workflow, "github.event.release.tag_name") {
		t.Fatalf("workflow must build immutable images from version tags:\n%s", workflow)
	}
	if err := service.UpdateEnvironmentDeployPolicy(context.Background(), UpdateEnvironmentDeployPolicyInput{EnvironmentID: environmentID, Mode: "always"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid deployment policy must be rejected: %v", err)
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
	configureTestWebhook(t, service, secret)
	now := time.Now().UTC()
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

func TestVersionTagAndReleaseQueueOnlyTheirConfiguredEnvironments(t *testing.T) {
	service := testService(t)
	ctx := context.Background()
	secret := "a-long-random-webhook-secret"
	configureTestWebhook(t, service, secret)
	repository := seedRepository(t, service)
	application, err := service.CreateApplication(ctx, CreateApplicationInput{
		RepositoryID: repository.ID, Name: "deployable-api", Type: AppTypeRESTAPI, Dockerfile: "Dockerfile", BuildContext: ".", ContainerPort: 8080,
		Environments: []CreateEnvironmentInput{
			{Name: "tag-preview", Type: EnvironmentTest, AutoDeployMode: AutoDeployTag},
			{Name: "production", Type: EnvironmentProduction, AutoDeployMode: AutoDeployRelease},
			{Name: "manual", Type: EnvironmentStaging, AutoDeployMode: AutoDeployManual},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	commitSHA := strings.Repeat("a", 40)
	tagPayload := map[string]any{
		"ref": "refs/tags/v3.1.4", "after": commitSHA, "created": true, "deleted": false,
		"repository": map[string]any{"id": 101, "full_name": "acme/platform"},
	}
	version, duplicate, err := sendTestWebhook(t, service, secret, "tag-v3-1-4", "push", tagPayload)
	if err != nil || duplicate || !version.TagDetected || version.ReleasePublished || len(version.Artifacts) != 1 {
		t.Fatalf("tag webhook did not create the expected version: %#v duplicate=%v err=%v", version, duplicate, err)
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	if err := service.MarkArtifact(ctx, version.Artifacts[0].ID, digest, ArtifactReady, ""); err != nil {
		t.Fatal(err)
	}
	environments := make(map[string]Environment, len(application.Environments))
	for _, environment := range application.Environments {
		environments[environment.Name] = environment
	}
	deploymentCount := func(environmentID string) int {
		var count int
		if err := service.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments WHERE environment_id=? AND trigger='auto'`, environmentID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if deploymentCount(environments["tag-preview"].ID) != 1 || deploymentCount(environments["production"].ID) != 0 || deploymentCount(environments["manual"].ID) != 0 {
		t.Fatal("tag detection queued an environment with the wrong deployment policy")
	}
	releasePayload := map[string]any{
		"action": "published", "repository": map[string]any{"id": 101, "full_name": "acme/platform"},
		"release": map[string]any{"tag_name": "v3.1.4", "target_commitish": "main", "name": "Release 3.1.4", "published_at": time.Now().UTC().Format(time.RFC3339), "draft": false, "prerelease": false},
	}
	published, duplicate, err := sendTestWebhook(t, service, secret, "release-v3-1-4", "release", releasePayload)
	if err != nil || duplicate || published.ID != version.ID || !published.TagDetected || !published.ReleasePublished || published.CommitSHA != commitSHA {
		t.Fatalf("published release did not converge with the tag version: %#v duplicate=%v err=%v", published, duplicate, err)
	}
	if deploymentCount(environments["tag-preview"].ID) != 1 || deploymentCount(environments["production"].ID) != 1 || deploymentCount(environments["manual"].ID) != 0 {
		t.Fatal("published release queued an environment with the wrong deployment policy")
	}
	if _, _, err := sendTestWebhook(t, service, secret, "release-v3-1-4-redelivery", "release", releasePayload); err != nil {
		t.Fatal(err)
	}
	if deploymentCount(environments["tag-preview"].ID) != 1 || deploymentCount(environments["production"].ID) != 1 {
		t.Fatal("automatic deployment was duplicated for the same environment and artifact")
	}
}

func TestRepositoryWebhookProcessesOnlySupportedLifecycleActions(t *testing.T) {
	service := testService(t)
	secret := "a-long-random-webhook-secret"
	configureTestWebhook(t, service, secret)

	if _, duplicate, err := sendTestWebhook(t, service, secret, "repo-created", "repository", repositoryWebhookPayload("created")); err != nil || duplicate {
		t.Fatalf("created repository webhook: duplicate=%v err=%v", duplicate, err)
	}
	repositories, err := service.ListRepositories(context.Background(), 10, 0)
	if err != nil || len(repositories) != 1 || repositories[0].Archived {
		t.Fatalf("created repository was not synchronized: %#v err=%v", repositories, err)
	}
	application := createTestApplication(t, service, repositories[0].ID, "events-api")

	ignored := repositoryWebhookPayload("edited")
	ignored["repository"].(map[string]any)["language"] = "Rust"
	if _, duplicate, err := sendTestWebhook(t, service, secret, "repo-edited", "repository", ignored); err != nil || duplicate {
		t.Fatalf("unsupported repository action must be acknowledged: duplicate=%v err=%v", duplicate, err)
	}
	repositories, err = service.ListRepositories(context.Background(), 10, 0)
	if err != nil || repositories[0].Language != "Go" {
		t.Fatalf("unsupported repository action changed state: %#v err=%v", repositories, err)
	}

	for index, action := range []string{"archived", "unarchived", "deleted"} {
		deliveryID := "repo-" + action
		if _, duplicate, err := sendTestWebhook(t, service, secret, deliveryID, "repository", repositoryWebhookPayload(action)); err != nil || duplicate {
			t.Fatalf("%s repository webhook: duplicate=%v err=%v", action, duplicate, err)
		}
		repositories, err = service.ListRepositories(context.Background(), 10, 0)
		if err != nil || len(repositories) != 1 {
			t.Fatalf("list after %s: %#v err=%v", action, repositories, err)
		}
		wantArchived := index != 1
		if repositories[0].Archived != wantArchived {
			t.Fatalf("%s archived=%v, want %v", action, repositories[0].Archived, wantArchived)
		}
	}

	if _, err := service.GetApplication(context.Background(), application.ID); err != nil {
		t.Fatalf("deleted repository event must preserve linked applications: %v", err)
	}
	if _, duplicate, err := sendTestWebhook(t, service, secret, "repo-deleted", "repository", repositoryWebhookPayload("deleted")); err != nil || !duplicate {
		t.Fatalf("repeated repository delivery must be idempotent: duplicate=%v err=%v", duplicate, err)
	}

	var audits, deliveries int
	if err := service.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'repository.%'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := service.store.db.QueryRow(`SELECT COUNT(*) FROM processed_webhooks WHERE event_type='repository'`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if audits != 4 || deliveries != 5 {
		t.Fatalf("unexpected repository webhook records: audits=%d deliveries=%d", audits, deliveries)
	}
}
