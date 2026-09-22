package appmanager

import (
	"errors"
	"testing"
)

func TestSingleGitHubInstallationRequiresExactlyOneValidAccount(t *testing.T) {
	if _, err := singleGitHubInstallation(nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero installations must be rejected: %v", err)
	}
	installations := []githubInstallation{{ID: 10}, {ID: 20}}
	if _, err := singleGitHubInstallation(installations); !errors.Is(err, ErrConflict) {
		t.Fatalf("multiple installations must be rejected: %v", err)
	}
	var valid githubInstallation
	valid.ID = 42
	valid.Account.Login = "acme"
	valid.Account.Type = "Organization"
	valid.Account.AvatarURL = "https://avatars.githubusercontent.com/u/1?v=4"
	installation, err := singleGitHubInstallation([]githubInstallation{valid})
	if err != nil || installation.ID != 42 || installation.Account.Login != "acme" {
		t.Fatalf("valid installation was not accepted: %#v %v", installation, err)
	}
}

func TestGeneratedWebhookSecretHasSufficientEntropy(t *testing.T) {
	first, err := newWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 40 || first == second {
		t.Fatalf("webhook secrets must be long and unique: %q %q", first, second)
	}
}
