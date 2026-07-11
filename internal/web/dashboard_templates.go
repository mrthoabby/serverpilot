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

func renderDashboardHTML() ([]byte, error) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		return nil, fmt.Errorf("parse dashboard templates: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "dashboard.html", nil); err != nil {
		return nil, fmt.Errorf("execute dashboard template: %w", err)
	}
	return buf.Bytes(), nil
}
