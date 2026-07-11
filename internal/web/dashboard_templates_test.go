package web

import (
	"strings"
	"testing"
)

func TestRenderDashboardHTML(t *testing.T) {
	html, err := renderDashboardHTML()
	if err != nil {
		t.Fatalf("renderDashboardHTML() error: %v", err)
	}
	body := string(html)
	checks := []string{
		"<!DOCTYPE html>",
		"id=\"loginScreen\"",
		"id=\"dashboard\"",
		"id=\"panel-containers\"",
		"id=\"associateModal\"",
		"/static/js/core.js",
		"/static/containers-sites.js",
		"</html>",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard HTML missing %q", want)
		}
	}
}
