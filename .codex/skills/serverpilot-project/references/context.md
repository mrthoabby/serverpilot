# ServerPilot Compact Context

## Quick Facts

- Module: `github.com/mrthoabby/serverpilot`
- Binary: `sp`
- Language: Go 1.26
- Main dependencies: Cobra, bcrypt/crypto, terminal password input, MySQL driver, PostgreSQL driver.
- Current version source: `version.go`
- Default dashboard port: `8090`
- Main persistent paths: `/etc/serverpilot`, `/etc/nginx`, `/var/lib/serverpilot`, `/opt`, `/var/log/serverpilot-scanners.log`
- The daemon is usually root via systemd.

## Commands

- `sp setup`: dependency check/install, admin credentials, optional dashboard SSL.
- `sp start [-d] [--port N]`: run dashboard in foreground or install/restart systemd service.
- `sp stop`, `sp status`: systemd service operations.
- `sp expose --domain <fqdn> [--port N]`: create Nginx reverse proxy for dashboard.
- `sp update`: self-update from latest GitHub release with tag validation and rollback smoke test.
- `sp credentials [--reset]`: show/reset admin credentials.
- `sp port [--min N --max N] [--list]`: reserve an available port for deploy workflows.

## Package Map

- `cmd`: Cobra commands and root privilege gate for privileged subcommands.
- `internal/auth`: config file, bcrypt auth, session secret, in-memory session store.
- `internal/web`: HTTP server, middleware, API handlers, embedded dashboard.
- `internal/docker`: `docker ps`, inspect, logs, image list/delete.
- `internal/nginx`: site listing, parsing, enable/disable, config read/write, domain validation.
- `internal/templates`: Nginx templates for API, NestJS, NextJS, Frontend, MinIO.
- `internal/mapper`: maps Docker host ports to Nginx `proxy_pass` entries.
- `internal/sysinfo`: system stats, disk breakdown/detail, process memory, guarded disk cleanup.
- `internal/users`: deploy users, SSH keys, gcloud firewall helpers.
- `internal/apps`: managed `/opt/<app>` directories and encrypted env-file transport.
- `internal/permissions`: ACL/group/sudoers grant service and audit.
- `internal/dbquery`: encrypted DB connection vault, query runner, schema browsing, audit.
- `internal/portalloc`: cross-process port reservation registry in `/var/lib/serverpilot`.
- `internal/labels` and `internal/cases`: dashboard metadata stored under `/etc/serverpilot`.

## Web Surface

- Route registration lives in `internal/web/server.go`.
- Handler implementations live in `internal/web/handlers.go`.
- Middleware lives in `internal/web/middleware.go`.
- The main UI is `internal/web/static/index.html` with embedded CSS/JS.
- Useful searches:
  - Handlers: `rg -n "^func \\(s \\*Server\\) handle" internal/web/handlers.go`
  - Routes: `rg -n "mux.Handle|mux.HandleFunc" internal/web/server.go`
  - Frontend calls: `rg -n "apiFetch\\(\"/api|fetch\\('/api" internal/web/static/index.html`

## Security Backlog To Remember

`SECURITY_REVIEW.md` documents a prior audit. Critical findings were patched, but these areas remain worth extra attention:

- `nginx.WriteConfigContent` still uses predictable `.tmp` and `.bak` paths around config validation.
- `templates.ApplyTemplate` and some settings handlers have historical path-containment patterns that should be reviewed before expanding them.
- `handleDependencyInstall` runs apt as root and should use a stronger confirm-token or locality gate if extended.
- User-controlled log values should be sanitized consistently.
- Binary update/install integrity is checksum-over-HTTPS/tag-pinning today; release signing would be stronger.

## Validation Notes

- There are currently no `*_test.go` files.
- `go test ./...` and `go vet ./...` pass on Go 1.26.3 in the local environment.
- If `go list`, `go test`, or `go vet` fail opening `~/Library/Caches/go-build` or `~/go/pkg/mod` in sandboxed Codex, rerun with `env GOCACHE=/private/tmp/serverpilot-go-cache GOMODCACHE=/private/tmp/serverpilot-go-modcache`.

## Release Notes

- Historical binaries are committed under `release/<version>/`.
- `vs-pre-run/Makefile` cross-compiles `linux-amd64`, `linux-arm64`, `darwin-amd64`, and `darwin-arm64`, then updates `homebrew/Formula/sp.rb`.
- Installer and updater fetch pinned tag paths under `raw.githubusercontent.com/mrthoabby/serverpilot/<tag>/release/<version>/`.
- Do not change `version.go` without considering release artifacts and formulas.
