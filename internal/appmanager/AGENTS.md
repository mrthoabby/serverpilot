# Application Manager Agent Notes

## Purpose

`internal/appmanager` is the vNext application control plane. It owns
the product model and persistence for GitHub repositories, applications,
application environments, projects, releases, image artifacts, deployments,
agents, configuration, resource monitoring, server settings, terminal access,
and audit events. The legacy Apps, deploy Users, Cases, and Server Tools UI are
retired; Database remains the only standalone dashboard module.

Application Manager is pre-production. Implement its current model directly:
do not add compatibility fallbacks, legacy-field inference, or migrations for
earlier Application Manager prototypes. Do not restore the removed Apps,
deploy Users, Cases, Permissions, GCloud firewall, dependency installer,
GD-App, or managed env-file flows.

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
- A repository tag and a GitHub Release with the same tag are one shared
  repository version. Each linked application receives an image artifact
  state, not an independent semantic version.
- Every application environment has exactly one deployment policy: `manual`,
  automatic on semantic version tag (`vMAJOR.MINOR.PATCH`), or automatic on a
  published GitHub Release. A tag-triggered deployment must not be repeated
  when the matching Release is later published.
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
- Subscribe the GitHub App to `Push`, `Release`, and `Repository`. For Push,
  process only newly created semantic version tag refs and reject silently
  moved tags. Process only `published` release actions and repository actions
  `created`, `deleted`, `archived`, and `unarchived`; acknowledge other signed
  actions without mutating state. Deleted repositories remain as archived
  records so linked applications and audit history are preserved.
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

- Application Manager is the default module after login. The global module
  switcher contains only Application Manager and Database; there is no legacy
  horizontal tab row or Server Tools module.
- There is no global Application Manager Overview screen. The default landing
  is the selected project; if no project exists, show Applications. An
  application's own Overview tab remains valid as its local summary.
- Inside the module, use the persistent sidebar with expandable Projects and
  Applications submenus plus Repositories, Resources, GitHub, and Settings.
- Resources owns CPU, memory, disk, uptime, container utilization, Docker disk
  usage and cleanup, largest-file inspection, and service health.
- Settings owns dashboard domain, SSL, insecure-traffic blocking, host guard,
  account/security preferences, and Terminal. Keep their privileged endpoint
  protections and reauthentication requirements unchanged during migration.
- Settings owns the user-facing Deployment setup guide. Keep its readiness
  states derived from live GitHub, repository, application/environment,
  registry, agent, and version data, and provide copy-ready workflow guidance.
- Scope all styles below `.app-manager`. Use the dark design tokens in
  `internal/web/static/css/app-manager.css`, English UI copy, line icons, clear
  focus states, and icon+text status semantics. Do not add runtime CDN assets.

## Validation

- Do not run `go get` or otherwise add/update dependencies. The repository
  owner manages dependency installation explicitly.
- Format touched Go files with `gofmt`.
- Run focused package tests, `go test ./...`, and `go vet ./...`.
- Visually verify the rendered module at desktop, tablet, and mobile widths.
