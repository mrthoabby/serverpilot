package appmanager

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestStoreMigratesDeploymentPoliciesAndVersionSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appmanager.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(1,CURRENT_TIMESTAMP);
CREATE TABLE application_environments(id TEXT PRIMARY KEY,application_id TEXT,agent_id TEXT,auto_deploy INTEGER NOT NULL DEFAULT 0);
CREATE TABLE repository_releases(id TEXT PRIMARY KEY,repository_id TEXT NOT NULL,published_at TIMESTAMP NOT NULL);
CREATE TABLE deployments(environment_id TEXT NOT NULL,artifact_id TEXT NOT NULL,status TEXT NOT NULL,trigger TEXT NOT NULL,created_at TIMESTAMP NOT NULL);
`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertColumn := func(table, wanted string) {
		t.Helper()
		rows, err := store.db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, columnType string
			var notNull, primaryKey int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				t.Fatal(err)
			}
			if name == wanted {
				return
			}
		}
		t.Fatalf("column %s.%s was not migrated", table, wanted)
	}
	assertColumn("application_environments", "auto_deploy_source")
	assertColumn("repository_releases", "tag_detected")
	assertColumn("repository_releases", "release_published")
	var version int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("unexpected schema version %d: %v", version, err)
	}
}
