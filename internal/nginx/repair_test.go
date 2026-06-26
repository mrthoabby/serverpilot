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
