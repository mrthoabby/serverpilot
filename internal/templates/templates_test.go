package templates

import (
	"strings"
	"testing"
)

func TestBuildDelayedRedirectHTMLEscapesMessageAndPreservesRequestURI(t *testing.T) {
	got := buildDelayedRedirectHTML("https://new.example.com", 7, `<script>alert("x")</script>`)

	if strings.Contains(got, "<script>") {
		t.Fatalf("buildDelayedRedirectHTML() did not escape script tag: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;alert") {
		t.Fatalf("buildDelayedRedirectHTML() missing escaped message: %s", got)
	}
	if !strings.Contains(got, `https://new.example.com$request_uri`) {
		t.Fatalf("buildDelayedRedirectHTML() did not preserve request_uri: %s", got)
	}
	if !strings.Contains(got, `content=\"7;url=https://new.example.com$request_uri\"`) {
		t.Fatalf("buildDelayedRedirectHTML() missing meta refresh delay: %s", got)
	}
}
