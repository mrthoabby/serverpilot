package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var dashboardJSFiles = []string{
	"static/env-editor.js",
	"static/js/core.js",
	"static/js/modules/containers.js",
	"static/js/modules/sites.js",
	"static/js/modules/images.js",
	"static/js/modules/mappings.js",
	"static/js/modules/container-logs.js",
	"static/js/modules/site-modals.js",
	"static/js/modules/modals.js",
	"static/js/modules/apps.js",
	"static/js/modules/ssh.js",
	"static/js/modules/database.js",
	"static/js/modules/permissions.js",
	"static/js/modules/users.js",
	"static/js/modules/gcp-firewall.js",
	"static/js/modules/settings.js",
	"static/js/modules/charts.js",
	"static/js/modules/memory.js",
	"static/js/modules/disk.js",
	"static/js/modules/stats.js",
	"static/js/modules/resources.js",
	"static/js/bootstrap.js",
	"static/containers-sites.js",
	"static/js/cases.js",
	"static/js/terminal.js",
}

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
		"id=\"settingsEmailLoginForm\"",
		"</html>",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard HTML missing %q", want)
		}
	}
}

func TestDashboardJSSyntax(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available for JavaScript syntax validation")
	}

	root := filepath.Join("..", "..")

	for _, rel := range dashboardJSFiles {
		path := filepath.Join(root, "internal", "web", rel)
		t.Run(rel, func(t *testing.T) {
			out, err := exec.Command("node", "--check", path).CombinedOutput()
			if err != nil {
				t.Fatalf("syntax check failed: %v\n%s", err, strings.TrimSpace(string(out)))
			}
		})
	}
}

func TestDashboardScriptLoadOrder(t *testing.T) {
	html, err := renderDashboardHTML()
	if err != nil {
		t.Fatalf("renderDashboardHTML() error: %v", err)
	}
	body := string(html)

	resourcesIdx := strings.Index(body, `src="/static/js/modules/resources.js"`)
	chartsIdx := strings.Index(body, `src="/static/js/modules/charts.js"`)
	memoryIdx := strings.Index(body, `src="/static/js/modules/memory.js"`)
	diskIdx := strings.Index(body, `src="/static/js/modules/disk.js"`)
	statsIdx := strings.Index(body, `src="/static/js/modules/stats.js"`)
	bootstrapIdx := strings.Index(body, `src="/static/js/bootstrap.js"`)
	containersSitesIdx := strings.Index(body, `src="/static/containers-sites.js"`)

	checks := map[string]int{
		"charts.js":           chartsIdx,
		"memory.js":           memoryIdx,
		"disk.js":             diskIdx,
		"stats.js":            statsIdx,
		"resources.js":        resourcesIdx,
		"bootstrap.js":        bootstrapIdx,
		"containers-sites.js": containersSitesIdx,
	}
	for name, idx := range checks {
		if idx < 0 {
			t.Fatalf("dashboard HTML missing %s script tag", name)
		}
	}

	if !(chartsIdx < memoryIdx && memoryIdx < diskIdx && diskIdx < statsIdx && statsIdx < resourcesIdx) {
		t.Fatalf("resource render modules must load before resources.js")
	}
	if !(resourcesIdx < containersSitesIdx && containersSitesIdx < bootstrapIdx) {
		t.Fatalf("containers-sites.js must load before bootstrap.js so loadContainers is fully wired")
	}
}

func TestDashboardJSNoSplitBoundaryRegressions(t *testing.T) {
	// v2.0.1 broke these modules by leaving loader bodies without function wrappers.
	cases := map[string][]string{
		"sites.js":      {"async function loadSites"},
		"images.js":     {"async function loadImages"},
		"mappings.js":   {"async function loadMappings"},
		"memory.js":     {"function formatMemDual("},
		"stats.js":      {"function renderContainerStats("},
		"containers.js": {"async function loadReplicas()", "async function loadContainers"},
	}
	root := filepath.Join("..", "..", "internal", "web", "static", "js", "modules")

	for rel, required := range cases {
		path := filepath.Join(root, rel)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(body)
		t.Run(rel, func(t *testing.T) {
			for _, needle := range required {
				if !strings.Contains(text, needle) {
					t.Fatalf("missing required wrapper %q (v2.0.1 regression)", needle)
				}
			}
		})
	}
}
