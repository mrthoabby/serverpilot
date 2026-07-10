package docker

import "testing"

func TestParseComposeLabels(t *testing.T) {
	meta := ParseComposeLabels(map[string]string{
		"com.docker.compose.project": "shop",
		"com.docker.compose.service": "web",
	})
	if !meta.IsCompose || meta.Project != "shop" || meta.Service != "web" {
		t.Fatalf("unexpected meta: %#v", meta)
	}
	if ParseComposeLabels(nil).IsCompose {
		t.Fatal("expected standalone container")
	}
}
