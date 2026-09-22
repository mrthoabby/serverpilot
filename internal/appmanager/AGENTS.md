# Application Manager Agent Notes

## Purpose

`internal/appmanager` is the isolated vNext application control plane. It owns
the product model and persistence for GitHub repositories, applications,
application environments, projects, releases, image artifacts, deployments,
agents, configuration, and audit events. It must not replace the legacy
`internal/apps` package or the existing Docker/Nginx dashboard.

Application Manager is pre-production. Implement its current model directly:
do not add compatibility fallbacks, legacy-field inference, or migrations for
earlier Application Manager prototypes. Compatibility work belongs only to
the established legacy ServerPilot flows.

The current cleanup release deliberately resets `/var/lib/serverpilot/appmanager`
once on its first daemon start and writes
`.cleanup-vnext-registry-username` so later restarts preserve new data. This is
temporary pre-production code: do not broaden its path or apply it to legacy
state. Remove the cleanup function and marker check only when the repository
owner explicitly requests the follow-up cleanup removal.

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
- The GitHub setup UI accepts only the App ID and private key. Discover the
  account login, account type, avatar, and Installation ID from GitHub; never
  trust manually copied identity metadata. Generate the webhook secret in
  ServerPilot and reveal it only once for GitHub App setup.
- GHCR credentials are optional for public images. Private-image access uses a
  separate registry username plus a classic PAT with `read:packages`; the
  token owner is not assumed to match the connected organization.
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

- The module is independent from the legacy horizontal dashboard tabs. Open it
  from the global module switcher/listbox, hide the legacy tab row while it is
  active, and keep the existing Apps tab intact.
- There is no global Application Manager Overview screen. The default landing
  is the selected project; if no project exists, show Applications. An
  application's own Overview tab remains valid as its local summary.
- Inside the module, use the persistent sidebar with expandable Projects and
  Applications submenus plus Repositories, GitHub, and Settings links.
- Scope all styles below `.app-manager`. Use the dark design tokens in
  `internal/web/static/css/app-manager.css`, English UI copy, line icons, clear
  focus states, and icon+text status semantics. Do not add runtime CDN assets.

## Validation

- Do not run `go get` or otherwise add/update dependencies. The repository
  owner manages dependency installation explicitly.
- Format touched Go files with `gofmt`.
- Run focused package tests, `go test ./...`, and `go vet ./...`.
- Visually verify the rendered module at desktop, tablet, and mobile widths.
