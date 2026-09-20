# Application Manager Agent Notes

## Purpose

`internal/appmanager` is the isolated vNext application control plane. It owns
the product model and persistence for GitHub repositories, applications,
application environments, projects, releases, image artifacts, deployments,
agents, configuration, and audit events. It must not replace the legacy
`internal/apps` package or the existing Docker/Nginx dashboard.

## Non-negotiable domain rules

- A repository may have many applications. Every application has exactly one
  repository, at least one environment, and zero or one project.
- A project must contain at least one application. Project creation and app
  assignment are one transaction. An application already assigned to a
  project is never reassigned implicitly.
- Environments belong only to applications. Every environment has a custom
  name and one type: `test`, `staging`, or `production`. Multiple environments
  may share a type.
- Environment variables have exactly two owners: a project or an application
  environment. There is no application-global configuration layer and no
  project deployment-environment layer.
- At deploy time project values are merged first, then application-environment
  values overwrite matching keys. Keep this merge O(p+e) with a map.
- Applications have no scope namespace and runtime variables never receive
  `PJ_`, `AP_`, or similar prefixes.
- A GitHub release is shared by repository and tag. Each linked application
  receives an image artifact state, not an independent semantic version.
- Managed images use
  `ghcr.io/{owner}/sp-{repository}-{application}:{release-tag}` and deployments
  prefer the immutable digest once resolved.

## Security and operations

- The daemon normally runs as root. Validate input at HTTP and package
  boundaries. Never construct shell commands.
- Dashboard mutations require POST, auth, CSRF, strict JSON, and recent
  reauthentication for secrets, deploys, rollbacks, GitHub credentials, sites,
  SSL, pairing, and destructive actions.
- GitHub webhooks require HMAC verification before payload processing and a
  unique delivery ID for idempotency.
- Secrets are write-only. Store them encrypted with AES-GCM under a dedicated
  0600 master key and never return plaintext through APIs or logs.
- Docker operations use structured, allowlisted arguments, module ownership
  labels, bounded timeouts, temporary 0600 env files, health checks, and safe
  rollback. Do not use Docker Compose, arbitrary SSH, or Docker-over-TCP.
- Remote agents accept only structured allowlisted jobs over outbound TLS.

## Persistence and performance

- SQLite lives at `/var/lib/serverpilot/appmanager/appmanager.db` and uses
  migrations, foreign keys, WAL, busy timeout, parameterized SQL, short
  transactions, bounded pagination, and indexed lookup fields.
- Avoid N+1 queries, unbounded goroutines, unbounded logs, and network calls
  inside database transactions. GitHub/GHCR reconciliation uses bounded
  concurrency, context cancellation, exponential backoff, and jitter.

## UI boundary

- The module is a new dashboard tab and keeps the existing Apps tab intact.
- Scope all styles below `.app-manager`. Use the dark design tokens in
  `internal/web/static/css/app-manager.css`, English UI copy, line icons, clear
  focus states, and icon+text status semantics. Do not add runtime CDN assets.

## Validation

- Format touched Go files with `gofmt`.
- Run focused package tests, `go test ./...`, and `go vet ./...`.
- Visually verify the rendered module at desktop, tablet, and mobile widths.
