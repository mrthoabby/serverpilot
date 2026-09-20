package appmanager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("database path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("database directory is unsafe")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure database directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("database path is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect database path: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open application manager database: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect application manager database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure application manager database: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?) ON CONFLICT(version) DO NOTHING`, schemaVersion, time.Now().UTC()); err != nil {
		return fmt.Errorf("record schema migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS github_connection (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  id TEXT NOT NULL UNIQUE,
  account_login TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK(account_type IN ('User','Organization')),
  avatar_url TEXT NOT NULL DEFAULT '',
  app_id INTEGER NOT NULL CHECK(app_id > 0),
  installation_id INTEGER NOT NULL CHECK(installation_id > 0),
  private_key_cipher TEXT NOT NULL,
  webhook_secret_cipher TEXT NOT NULL,
  registry_pat_cipher TEXT NOT NULL DEFAULT '',
  last_synced_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
  id TEXT PRIMARY KEY,
  github_id INTEGER NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  full_name TEXT NOT NULL UNIQUE,
  default_branch TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT '',
  private INTEGER NOT NULL DEFAULT 0,
  html_url TEXT NOT NULL,
  archived INTEGER NOT NULL DEFAULT 0,
  last_synced_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id) ON DELETE RESTRICT,
  repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL CHECK(type IN ('nextjs','rest-api')),
  dockerfile TEXT NOT NULL,
  build_context TEXT NOT NULL,
  container_port INTEGER NOT NULL CHECK(container_port BETWEEN 1 AND 65535),
  image_name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_applications_repository ON applications(repository_id);
CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash BLOB NOT NULL DEFAULT X'',
  status TEXT NOT NULL CHECK(status IN ('local','offline','online')),
  version TEXT NOT NULL DEFAULT '',
  last_heartbeat_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS application_environments (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('test','staging','production')),
  agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
  container_name TEXT NOT NULL UNIQUE,
  container_port INTEGER NOT NULL CHECK(container_port BETWEEN 1 AND 65535),
  host_port INTEGER CHECK(host_port IS NULL OR host_port BETWEEN 1 AND 65535),
  domain TEXT NOT NULL DEFAULT '',
  site_enabled INTEGER NOT NULL DEFAULT 0,
  ssl_enabled INTEGER NOT NULL DEFAULT 0,
  health_path TEXT NOT NULL DEFAULT '',
  auto_deploy INTEGER NOT NULL DEFAULT 0,
  current_artifact_id TEXT,
  status TEXT NOT NULL DEFAULT 'idle',
  last_deployment_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE(application_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_environments_application ON application_environments(application_id);
CREATE INDEX IF NOT EXISTS idx_environments_agent ON application_environments(agent_id);
CREATE TABLE IF NOT EXISTS configuration_entries (
  id TEXT PRIMARY KEY,
  owner_type TEXT NOT NULL CHECK(owner_type IN ('project','environment')),
  owner_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value_cipher TEXT NOT NULL,
  secret INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE(owner_type, owner_id, key)
);
CREATE INDEX IF NOT EXISTS idx_configuration_owner ON configuration_entries(owner_type, owner_id);
CREATE TABLE IF NOT EXISTS repository_releases (
  id TEXT PRIMARY KEY,
  repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  published_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(repository_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_releases_repository ON repository_releases(repository_id, published_at DESC);
CREATE TABLE IF NOT EXISTS application_release_artifacts (
  id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES repository_releases(id) ON DELETE CASCADE,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  image_reference TEXT NOT NULL,
  image_digest TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK(status IN ('waiting_for_image','ready','failed','timed_out')),
  last_checked_at TIMESTAMP,
  failure_code TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE(release_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_status ON application_release_artifacts(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_application ON application_release_artifacts(application_id, created_at DESC);
CREATE TABLE IF NOT EXISTS deployments (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES application_environments(id) ON DELETE RESTRICT,
  artifact_id TEXT NOT NULL REFERENCES application_release_artifacts(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK(status IN ('queued','running','success','failed','canceled')),
  trigger TEXT NOT NULL CHECK(trigger IN ('manual','auto','rollback')),
  actor TEXT NOT NULL,
  container_name TEXT NOT NULL DEFAULT '',
  image_digest TEXT NOT NULL DEFAULT '',
  log_summary TEXT NOT NULL DEFAULT '',
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deployments_environment ON deployments(environment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_deployments_one_active ON deployments(environment_id) WHERE status IN ('queued','running');
CREATE TABLE IF NOT EXISTS pairing_tokens (
  id TEXT PRIMARY KEY,
  token_hash BLOB NOT NULL UNIQUE,
  name TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairing_expiry ON pairing_tokens(expires_at);
CREATE TABLE IF NOT EXISTS agent_jobs (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','success','failed','canceled')),
  result_code TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_queue ON agent_jobs(agent_id, status, created_at);
CREATE TABLE IF NOT EXISTS processed_webhooks (
  delivery_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
`
