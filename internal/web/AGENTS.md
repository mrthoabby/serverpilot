# ServerPilot Web Notes

## Scope

These notes apply to `internal/web/**`.

`server.go` registers routes and middleware. `handlers.go` is the main API surface. `static/index.html` is the real dashboard UI and includes most CSS and JavaScript inline.

## How To Navigate

- List handlers: `rg -n "^func \\(s \\*Server\\) handle" internal/web/handlers.go`.
- Find route registration: `rg -n "mux.Handle|mux.HandleFunc" internal/web/server.go`.
- Find frontend calls: `rg -n "apiFetch\\(\"/api|fetch\\('/api" internal/web/static/index.html`.
- Find a tab: `rg -n "data-tab=\"<name>\"|id=\"<name>" internal/web/static/index.html`.
- Treat `static/app.js` and `static/style.css` as legacy unless `index.html` references them.

## Handler Pattern

- Start with an explicit HTTP method check.
- For JSON bodies, use `jsonDecode`.
- Validate length, enum, regex, port, CIDR, domain, username, and path inputs before calling internal packages.
- Re-validate in the package that touches files, commands, Docker, Nginx, users, DBs, or permissions.
- Return `apiResponse` through `writeJSON`; avoid exposing raw command output unless the endpoint is intentionally streaming progress.

## Frontend Pattern

- Use existing `apiFetch` and `showToast` helpers.
- Keep UI state colocated with the tab/function already handling that domain.
- Escape dynamic HTML with existing escaping helpers before interpolation.
- If adding a state-changing endpoint call, verify it sends POST and goes through `apiFetch` so CSRF-relevant headers/body handling stay consistent.

## Sensitive Areas

- `handleUpdate`, `handleDependencyInstall`, disk cleanup, firewall, permissions, users, Nginx config save, managed app/env-file handlers, DB query execution, and SSH private-key vault endpoints need extra review.
- Changes that write under `/etc`, `/opt`, `/var/lib`, `/var/log`, `/usr/local/bin`, or invoke system tools should include tests or a clear manual verification path.

