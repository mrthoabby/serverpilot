package nginx

import (
	"strings"
	"testing"
)

func TestAddWWWAliasToConfigAddsAliasToAllMatchingServerNames(t *testing.T) {
	content := strings.Join([]string{
		"server {",
		"    listen 80;",
		"    server_name example.com;",
		"}",
		"server {",
		"    listen 443 ssl;",
		"    server_name example.com; # managed by certbot",
		"}",
		"",
	}, "\n")

	got, changed, err := AddWWWAliasToConfig(content, "example.com")
	if err != nil {
		t.Fatalf("AddWWWAliasToConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("AddWWWAliasToConfig() changed = false, want true")
	}
	if strings.Count(got, "server_name example.com www.example.com;") != 2 {
		t.Fatalf("updated config did not add www alias to both server_name directives:\n%s", got)
	}
	if !strings.Contains(got, "server_name example.com www.example.com; # managed by certbot") {
		t.Fatalf("updated config did not preserve trailing comment:\n%s", got)
	}
}

func TestAddWWWAliasToConfigDoesNotDuplicateAlias(t *testing.T) {
	content := "server {\n    server_name example.com www.example.com;\n}\n"

	got, changed, err := AddWWWAliasToConfig(content, "example.com")
	if err != nil {
		t.Fatalf("AddWWWAliasToConfig() error = %v", err)
	}
	if changed {
		t.Fatal("AddWWWAliasToConfig() changed = true, want false")
	}
	if got != content {
		t.Fatalf("AddWWWAliasToConfig() changed content unexpectedly:\n%s", got)
	}
}

func TestAddWWWAliasToConfigRejectsWWWPrimaryDomain(t *testing.T) {
	if _, _, err := AddWWWAliasToConfig("server_name www.example.com;\n", "www.example.com"); err == nil {
		t.Fatal("expected error for primary domain that already starts with www")
	}
}

func TestPrimaryServerNamePrefersNonWWWName(t *testing.T) {
	names := []string{"www.example.com", "example.com"}
	if got := primaryServerName(names); got != "example.com" {
		t.Fatalf("primaryServerName() = %q, want %q", got, "example.com")
	}
}

func TestHasWWWAliasRequiresPrimaryAndAlias(t *testing.T) {
	if !hasWWWAlias("example.com", []string{"example.com", "www.example.com"}) {
		t.Fatal("hasWWWAlias() = false, want true")
	}
	if hasWWWAlias("example.com", []string{"www.example.com"}) {
		t.Fatal("hasWWWAlias() = true with alias only, want false")
	}
}

func TestSecurityCatchAllConfigUsesPlainNotFoundResponse(t *testing.T) {
	if !strings.Contains(securityCatchAllHTTPOnlyConfig, "listen 80 default_server;") {
		t.Fatal("catch-all config must be the HTTP default_server")
	}
	if !strings.Contains(securityCatchAllHTTPOnlyConfig, `return 404 "Site not found\n";`) {
		t.Fatal("catch-all config must return the plain Site not found response")
	}
}
