package appmanager

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateApplicationAndProjectInvariants(t *testing.T) {
	valid := CreateApplicationInput{
		RepositoryID: strings.Repeat("a", 32), Name: "orders-api", Type: AppTypeRESTAPI,
		Dockerfile: "Dockerfile", BuildContext: ".", ContainerPort: 8080,
		Environments: []CreateEnvironmentInput{{Name: "qa", Type: EnvironmentTest}, {Name: "integration", Type: EnvironmentTest}},
	}
	withoutRepository := valid
	withoutRepository.RepositoryID = ""
	if !errors.Is(ValidateCreateApplication(withoutRepository), ErrInvalid) {
		t.Fatal("application without repository must be rejected")
	}
	withoutEnvironments := valid
	withoutEnvironments.Environments = nil
	if !errors.Is(ValidateCreateApplication(withoutEnvironments), ErrInvalid) {
		t.Fatal("application without environments must be rejected")
	}
	if err := ValidateCreateApplication(valid); err != nil {
		t.Fatalf("multiple environments of the same type should be valid: %v", err)
	}
	invalidType := valid
	invalidType.Environments = []CreateEnvironmentInput{{Name: "sandbox", Type: "development"}}
	if !errors.Is(ValidateCreateApplication(invalidType), ErrInvalid) {
		t.Fatal("unsupported environment type must be rejected")
	}
	if !errors.Is(ValidateCreateProject(CreateProjectInput{Name: "Empty"}), ErrInvalid) {
		t.Fatal("project without applications must be rejected")
	}
}

func TestMergeVariablesEnvironmentWins(t *testing.T) {
	project := []ResolvedVariable{{Key: "API_URL", Value: "https://api.example.com"}, {Key: "LOG_LEVEL", Value: "info"}, {Key: "JWT_SECRET", Value: "project", Secret: true}}
	environment := []ResolvedVariable{{Key: "API_URL", Value: "https://staging-api.example.com"}, {Key: "NEXT_PUBLIC_ANALYTICS", Value: "false"}, {Key: "JWT_SECRET", Value: "environment", Secret: true}}
	got := MergeVariables(project, environment)
	values := make(map[string]ResolvedVariable, len(got))
	for _, item := range got {
		values[item.Key] = item
	}
	if len(values) != 4 || values["API_URL"].Value != "https://staging-api.example.com" || values["LOG_LEVEL"].Value != "info" {
		t.Fatalf("unexpected merge result: %#v", got)
	}
	if values["JWT_SECRET"].Value != "environment" || !values["JWT_SECRET"].Secret {
		t.Fatal("environment secret must override project secret")
	}
}

func TestImageConventionAndCollisionSuffix(t *testing.T) {
	image, err := ImageRepository("Acme", "Platform", "Storefront")
	if err != nil {
		t.Fatal(err)
	}
	if image != "ghcr.io/acme/sp-platform-storefront" {
		t.Fatalf("unexpected conventional image: %s", image)
	}
	one, err := ImageRepository("acme", "platform", "shop_front")
	if err != nil {
		t.Fatal(err)
	}
	two, err := ImageRepository("acme", "platform", "shop-front")
	if err != nil {
		t.Fatal(err)
	}
	if one == two || !strings.HasPrefix(one, "ghcr.io/acme/sp-platform-shop-front-") {
		t.Fatalf("lossy normalization must receive a deterministic collision suffix: %s / %s", one, two)
	}
	ref, err := ImageReference(image, "v2.14.3", "")
	if err != nil || ref != image+":v2.14.3" {
		t.Fatalf("unexpected release reference: %s (%v)", ref, err)
	}
	if _, err := ImageReference(image, "latest", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("latest must not be deployable")
	}
}

func TestGitHubWebhookOfficialSignatureVector(t *testing.T) {
	const signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if !verifyGitHubSignature("It's a Secret to Everybody", []byte("Hello, World!"), signature) {
		t.Fatal("GitHub's documented HMAC-SHA256 test vector must validate")
	}
	if verifyGitHubSignature("wrong", []byte("Hello, World!"), signature) {
		t.Fatal("invalid webhook secret must not validate")
	}
}
