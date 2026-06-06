# ServerPilot Agent Notes

## Purpose

ServerPilot is a Go CLI named `sp` plus an embedded web dashboard for managing Docker containers, Nginx reverse proxies, SSL/certbot, deploy users, managed `/opt` apps, database query connections, permissions, system resources, and self-updates on Linux servers.

The daemon and many CLI commands run as root. Treat every change as privileged server-management code, not as a normal web app.

## Token Discipline

- Prefer `rg --files` and targeted `rg -n` searches before opening files.
- Do not read binaries in `release/**`. Use `ls`, `file`, or hashes only when a release task needs them.
- Ignore historical Homebrew formulas `homebrew/Formula/sp@*.rb` unless the task is about release history.
- For UI work, search `internal/web/static/index.html` by tab id, endpoint, or function name. It is large and has embedded CSS/JS.
- Use `SECURITY_REVIEW.md` as backlog context, not as a file to reread every turn.

## Standard Commands

- Format touched Go files: `gofmt -w <files>`.
- Validate all packages: `go test ./...` and `go vet ./...`.
- If Go cache writes fail under sandboxing, use writable caches:
  `mkdir -p /private/tmp/serverpilot-go-cache`
  `mkdir -p /private/tmp/serverpilot-go-modcache`
  `env GOCACHE=/private/tmp/serverpilot-go-cache GOMODCACHE=/private/tmp/serverpilot-go-modcache go test ./...`
  `env GOCACHE=/private/tmp/serverpilot-go-cache GOMODCACHE=/private/tmp/serverpilot-go-modcache go vet ./...`
- Build local binary: `go build -o sp .`.
- Release builds are driven from `vs-pre-run/Makefile`; do not run release targets unless the user asks for a release/version change.

## Architecture Map

- `main.go` wires `cmd.SetVersion(Version)` and `cmd.Execute()`.
- `version.go` holds the shipped version string.
- `cmd/` contains Cobra commands: `setup`, `start`, `stop`, `status`, `expose`, `update`, `credentials`, and `port`.
- `internal/web/` contains the embedded dashboard, route registration, handlers, middleware, and static files.
- `internal/auth/` stores `/etc/serverpilot/config.json`, bcrypt password hashes, session secret, SSL settings, and in-memory sessions.
- `internal/docker/`, `internal/nginx/`, `internal/templates/`, and `internal/mapper/` handle Docker inspection, Nginx site parsing/writes, vhost templates, and container-site mapping.
- `internal/sysinfo/` collects system/disk/memory/process data and performs guarded disk cleanup.
- `internal/users/`, `internal/apps/`, and `internal/permissions/` manage deploy users, `/opt/<app>` app directories, env files, ACLs, groups, and sudoers fragments.
- `internal/dbquery/` manages encrypted DB connection vaults, bounded SQL execution, cell updates, schema browsing, and audit logs.
- `internal/portalloc/` reserves deploy ports in `/var/lib/serverpilot`.

## Security Rules

- Validate untrusted input at the web handler and again at the package boundary when a package touches the OS.
- Avoid shell execution. Use `exec.Command` with fixed binary paths and separate arguments. Never build shell strings from user input.
- Prefer absolute command paths from `internal/deps` or vetted constants for Docker, Nginx, systemctl, apt, certbot, setfacl, gpasswd, and visudo.
- For path containment, use `filepath.Clean`, `filepath.Abs`, `filepath.Rel`, `filepath.EvalSymlinks`, and `os.Lstat`. Do not use `strings.HasPrefix` as the only containment check.
- For privileged writes, prefer `os.CreateTemp` in the same directory, restrictive permissions, `Sync`, `Close`, and atomic `Rename`. Use `O_EXCL` where overwriting would be dangerous.
- Refuse to overwrite production Nginx configs unless the workflow explicitly proves it is safe.
- Redact or sanitize user-controlled values in logs. Keep API errors generic when they could expose paths, DSNs, credentials, command output, or host details.
- Destructive or high-impact web actions should use POST, auth, CSRF checks, method guards, strict JSON decoding, and a confirm-token pattern when practical.

## Web API Rules

- Add routes in `internal/web/server.go`, then implement `func (s *Server) handle...` in `internal/web/handlers.go`.
- Protected routes must be wrapped with `s.authMiddleware`.
- JSON POST handlers should call `jsonDecode`, which rejects unknown fields and trailing data.
- Use `writeJSON` for API responses.
- Keep middleware ordering in `server.go` intentional: recovery, logging, security, CSRF, client-header checks, body limit, then routes.

## Testing Expectations

- This repo currently has no `*_test.go` files. For new logic, add focused tests when possible, especially for validators, path containment, template rendering, SQL query bounds, permission grants, and update/install safety.
- For handler changes, verify method rejection, auth behavior, CSRF behavior for state-changing requests, request body validation, and sanitized error output.
- For release/install changes, verify `install.sh`, `cmd/update.go`, Homebrew formula URLs/hashes, `version.go`, and `release/<version>/` artifacts together.
