package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"sync"
)

//go:embed templates/*.html templates/partials/*.html
var dashboardTemplatesFS embed.FS

var (
	dashboardTmpl     *template.Template
	dashboardTmplOnce sync.Once
	dashboardTmplErr  error
)

func loadDashboardTemplate() (*template.Template, error) {
	dashboardTmplOnce.Do(func() {
		dashboardTmpl, dashboardTmplErr = template.ParseFS(
			dashboardTemplatesFS,
			"templates/dashboard.html",
			"templates/partials/*.html",
		)
	})
	return dashboardTmpl, dashboardTmplErr
}

// dashboardTemplateData is passed to the dashboard HTML templates so asset URLs
// can include a version query string for cache-busting after deploys.
type dashboardTemplateData struct {
	Version string
}

func renderDashboardHTML(version string) ([]byte, error) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		return nil, fmt.Errorf("parse dashboard templates: %w", err)
	}
	var buf bytes.Buffer
	data := dashboardTemplateData{Version: version}
	if err := tmpl.ExecuteTemplate(&buf, "dashboard.html", data); err != nil {
		return nil, fmt.Errorf("execute dashboard template: %w", err)
	}
	return buf.Bytes(), nil
}
