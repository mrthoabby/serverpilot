# ServerPilot Web Notes

## Scope

These notes apply to `internal/web/**`.

`server.go` registers routes and middleware. `handlers.go` is the main API surface. The dashboard HTML is composed from Go `html/template` partials under `templates/` and rendered at startup into a cached byte slice served by `handleDashboard`.

## Dashboard Layout

| Area | Location |
|------|----------|
| HTML partials (100–330 lines each) | `templates/partials/*.html` |
| Root template | `templates/dashboard.html` |
| Template embed + render | `dashboard_templates.go` |
| CSS | `static/css/{base,login,layout,components,tabs}.css` |
| JS core (auth, state, tabs) | `static/js/core.js` |
| JS feature modules | `static/js/modules/*.js` |
| JS bootstrap (init + exports) | `static/js/bootstrap.js` |
| Container-centric sites UX | `static/containers-sites.js` |
| Cases tab | `static/js/cases.js` |
| Terminal tab | `static/js/terminal.js` |
| Env editor widget | `static/env-editor.js` |

Parciales HTML are embedded separately from `/static/` (not publicly served as raw files). Static assets under `static/` are served at `/static/` via `go:embed`.

## How To Navigate

- List handlers: `rg -n "^func \\(s \\*Server\\) handle" internal/web/handlers.go`.
- Find route registration: `rg -n "mux.Handle|mux.HandleFunc" internal/web/server.go`.
- Find frontend API calls: `rg -n "apiFetch\\(\"/api" internal/web/static/js`.
- Find a tab panel: `rg -n "id=\"panel-<name>\"" internal/web/templates/partials`.
- Find a modal: `rg -n "id=\"<name>Modal\"" internal/web/templates/partials`.
- Shared JS state/helpers: `static/js/core.js` and `window.SP` namespace in `static/js/bootstrap.js`.

## Handler Pattern

- Start with an explicit HTTP method check.
- For JSON bodies, use `jsonDecode`.
- Validate length, enum, regex, port, CIDR, domain, username, and path inputs before calling internal packages.
- Re-validate in the package that touches files, commands, Docker, Nginx, users, DBs, or permissions.
- Return `apiResponse` through `writeJSON`; avoid exposing raw command output unless the endpoint is intentionally streaming progress.

## Frontend Pattern

- Use `apiFetch` and `showToast` from `core.js` (also exposed on `window.*` for legacy scripts).
- New code should prefer `window.SP` namespace when adding cross-module APIs.
- Escape dynamic HTML with `escapeHtml` / `setText` before interpolation.
- State-changing calls must use POST via `apiFetch` so CSRF/reauth handling stays consistent.
- Script load order is defined in `templates/partials/scripts.html`; preserve it when adding modules.

## Sensitive Areas

- `handleUpdate`, `handleDependencyInstall`, disk cleanup, firewall, permissions, users, Nginx config save, managed app/env-file handlers, DB query execution, and SSH private-key vault endpoints need extra review.
- Changes that write under `/etc`, `/opt`, `/var/lib`, `/var/log`, `/usr/local/bin`, or invoke system tools should include tests or a clear manual verification path.
