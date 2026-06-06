---
name: serverpilot-project
description: Use when working in the ServerPilot repository, the sp CLI, Docker/Nginx dashboard, Go web handlers, privileged Linux server management, release/install flow, or security-hardening tasks for /Users/dabadia/dev/own/dply/serverpilot.
---

# ServerPilot Project Skill

Use this skill to operate on ServerPilot with compact context and safe defaults.

## Workflow

1. Read `AGENTS.md` first for repository-wide rules.
2. For non-trivial tasks, read `references/context.md` for the compact architecture and command map.
3. For web/dashboard tasks, also read `internal/web/AGENTS.md`.
4. For release artifact tasks, also read `release/AGENTS.md`.
5. Search before reading large files. In particular, use targeted `rg` in `internal/web/static/index.html` instead of opening the whole file.
6. Validate with `gofmt`, `go test ./...`, and `go vet ./...` when Go code changes. Use `/private/tmp/serverpilot-go-cache` for `GOCACHE` and `/private/tmp/serverpilot-go-modcache` for `GOMODCACHE` if sandbox cache permissions fail.

## Operating Bias

- Keep changes scoped; this project has many privileged file and command paths.
- Preserve existing hardening patterns: strict validation, no shell concatenation, atomic writes, path containment with `filepath.Rel`, auth plus CSRF on state-changing API calls, and sanitized logs/errors.
- Add focused tests for new validators, path logic, package-level OS boundaries, and release/update safety when practical.
