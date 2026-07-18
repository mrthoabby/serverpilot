package nginx

import (
	"strings"
	"testing"
)

func TestDedupeSingletonDirectivesInLocations(t *testing.T) {
	before := `server {
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
`
	after, changed := dedupeSingletonDirectivesInLocations(before)
	if !changed {
		t.Fatal("expected duplicate removal")
	}
	if strings.Count(after, "proxy_http_version") != 1 {
		t.Fatalf("expected one proxy_http_version, got:\n%s", after)
	}
}

func TestDedupeSingletonDirectivesNoChange(t *testing.T) {
	config := `location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
}
`
	_, changed := dedupeSingletonDirectivesInLocations(config)
	if changed {
		t.Fatal("expected no change")
	}
}

func TestNginxErrorDetailExtractsEmergLines(t *testing.T) {
	output := "nginx config test failed: nginx: [emerg] duplicate location \"/\" in /etc/nginx/sites-enabled/foo.example.com:12\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"
	detail := nginxErrorDetail(output)
	if detail == "" {
		t.Fatal("expected non-empty detail")
	}
	if !strings.Contains(detail, "[emerg]") {
		t.Fatalf("expected emerg line in detail, got %q", detail)
	}
	if !strings.Contains(detail, "foo.example.com:12") {
		t.Fatalf("expected file reference in detail, got %q", detail)
	}
}

func TestParseNginxTestIssuesServerNamesHash(t *testing.T) {
	output := "nginx config test failed: nginx: [emerg] could not build server_names_hash, you should increase server_names_hash_bucket_size: 64\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"
	issues := parseNginxTestIssues(output)
	if len(issues) == 0 {
		t.Fatal("expected at least one issue")
	}
	issue := issues[0]
	if issue.Kind != "server_names_hash" {
		t.Fatalf("expected server_names_hash kind, got %q", issue.Kind)
	}
	if !issue.AutoFixable {
		t.Fatal("expected server_names_hash to be auto-fixable")
	}
	if issue.Message == "" {
		t.Fatal("expected real error message")
	}
}

func TestParseNginxTestIssuesFileLine(t *testing.T) {
	output := "nginx config test failed: nginx: [emerg] duplicate location \"/\" in /etc/nginx/sites-enabled/foo.example.com:12\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"
	issues := parseNginxTestIssues(output)
	if len(issues) == 0 {
		t.Fatal("expected at least one issue")
	}
	issue := issues[0]
	if issue.File != "foo.example.com" {
		t.Fatalf("expected file foo.example.com, got %q", issue.File)
	}
	if issue.Line != 12 {
		t.Fatalf("expected line 12, got %d", issue.Line)
	}
	if !issue.AutoFixable {
		t.Fatal("expected duplicate directive to be auto-fixable")
	}
	if strings.Contains(issue.Message, "use server logs for details") {
		t.Fatalf("expected real message, got %q", issue.Message)
	}
}

func TestParseNginxTestIssuesUnknownErrorNotAutoFixable(t *testing.T) {
	output := "nginx config test failed: nginx: [emerg] unknown directive \"bad_thing\" in /etc/nginx/sites-enabled/broken.conf:3\n"
	issues := parseNginxTestIssues(output)
	if len(issues) == 0 {
		t.Fatal("expected at least one issue")
	}
	issue := issues[0]
	if issue.AutoFixable {
		t.Fatal("expected unknown error to require manual intervention")
	}
	if issue.File != "broken.conf" {
		t.Fatalf("expected broken.conf, got %q", issue.File)
	}
	if issue.Line != 3 {
		t.Fatalf("expected line 3, got %d", issue.Line)
	}
}
