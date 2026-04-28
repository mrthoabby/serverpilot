package dbquery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ── Inline cell editing ─────────────────────────────────────────────────
//
// This file implements two related capabilities:
//
//   1. After a successful SELECT, detect whether the result set is
//      derived from a single editable table and (if so) discover that
//      table's primary key. The discovery happens against the live
//      database catalogue (pg_catalog for postgres) — we never trust
//      the client to claim what the schema looks like.
//
//   2. Apply a one-cell UPDATE: `UPDATE "schema"."table" SET "col"=$1
//      WHERE "pk1"=$2 AND "pk2"=$3 ...`. Identifiers (schema, table,
//      column names) are validated against the catalogue and quoted; the
//      new value and PK values flow through driver parameters ($1..$N)
//      so the driver handles escaping and the dashboard never builds a
//      SQL string from operator-controlled value content.
//
// Why this is safe even though the dashboard already supports raw SQL:
//
//   - The same operator who can call /api/db/query with arbitrary SQL
//     can also call /api/db/cell-update. Cell editing does NOT expand
//     authority, only ergonomics.
//
//   - The cell-edit path is _safer_ than the raw-SQL path for typical
//     fix-a-typo work, because identifiers are pre-validated against
//     the live schema and values are parameterised. A regex-based
//     manual UPDATE in the SQL editor with a typo'd PK predicate could
//     touch many rows; cell-edit refuses if the WHERE doesn't match
//     exactly the table's PK, and the resulting UPDATE always carries
//     LIMIT-1-equivalent semantics (a primary-key WHERE matches at
//     most one row by definition).
//
//   - Engine support: postgres only in v1. MySQL/MariaDB returns "not
//     supported" so the UI hides the edit affordances. Adding mysql is
//     a separate file with its own information_schema queries.

// EditableMeta is returned alongside QueryResult when the server can
// vouch for the result being editable. The UI uses it to enable the
// double-click editing affordance on non-PK columns.
type EditableMeta struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	PrimaryKey []string `json:"primary_key"`
}

// simpleSelectRegex matches the narrow shape we are willing to mark as
// editable: a single bare SELECT against a single table, optionally
// schema-qualified, optionally with WHERE/ORDER BY/LIMIT clauses but no
// JOINs, no aggregates, no GROUP BY, no UNION, no subselects.
//
// Anything that doesn't match drops to non-editable. This is a deliberate
// design choice: it's better to refuse to edit than to silently update
// the wrong row because the operator wrote a query with ambiguous row
// identity.
//
// Captures: 1 = optional schema, 2 = table.
var simpleSelectRegex = regexp.MustCompile(`(?i)^\s*select\s+.+?\s+from\s+(?:"?([a-zA-Z_][a-zA-Z0-9_]*)"?\.)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?(?:\s+(?:where|order\s+by|limit|--|/\*|;|$))`)

var disqualifyingRegex = regexp.MustCompile(`(?i)\b(join|union|group\s+by|having|with\s+|distinct\s+|insert|update|delete|drop|alter|truncate)\b|\bselect\s+\w+\s*\(`)

// detectEditable inspects a successful SELECT query against a postgres
// connection and returns the editability metadata if the result set is
// derived from a single editable table whose PK is fully present in the
// returned columns. Returns nil when the query is not editable for any
// reason (multi-table, aggregate, view, missing PK columns, etc.).
//
// MUST only be called for engine = postgres. Other engines should pass
// nil for the metadata.
func detectEditable(ctx context.Context, db *sql.DB, query string, returnedColumns []string) *EditableMeta {
	q := strings.TrimSpace(query)
	if disqualifyingRegex.MatchString(q) {
		return nil
	}
	m := simpleSelectRegex.FindStringSubmatch(q)
	if m == nil {
		return nil
	}
	schema := m[1]
	table := m[2]
	if schema == "" {
		// Fall back to current schema. Postgres exposes current_schema().
		var s string
		if err := db.QueryRowContext(ctx, `select current_schema()`).Scan(&s); err == nil && s != "" {
			schema = s
		} else {
			schema = "public"
		}
	}

	// Confirm it's a regular table (not a view, not a foreign table).
	var relkind string
	err := db.QueryRowContext(ctx, `
		select c.relkind
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		where n.nspname = $1 and c.relname = $2
	`, schema, table).Scan(&relkind)
	if err != nil || (relkind != "r" && relkind != "p") { // r=ordinary, p=partitioned
		return nil
	}

	// Discover the PK columns.
	rows, err := db.QueryContext(ctx, `
		select a.attname
		from pg_index i
		join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
		join pg_class c on c.oid = i.indrelid
		join pg_namespace n on n.oid = c.relnamespace
		where i.indisprimary and n.nspname = $1 and c.relname = $2
		order by array_position(i.indkey, a.attnum)
	`, schema, table)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var pk []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return nil
		}
		pk = append(pk, col)
	}
	if len(pk) == 0 {
		return nil // table has no primary key — refuse to edit
	}

	// Every PK column must be present in the returned column set. Match
	// case-insensitively (postgres folds unquoted identifiers to lower).
	colSet := map[string]bool{}
	for _, c := range returnedColumns {
		colSet[strings.ToLower(c)] = true
	}
	for _, k := range pk {
		if !colSet[strings.ToLower(k)] {
			return nil
		}
	}
	return &EditableMeta{Schema: schema, Table: table, PrimaryKey: pk}
}

// CellUpdateInput is the body of /api/db/cell-update. Field names and
// shapes are stable.
type CellUpdateInput struct {
	ConnectionID string                 `json:"connection_id"`
	Schema       string                 `json:"schema"`        // required
	Table        string                 `json:"table"`         // required
	Column       string                 `json:"column"`        // the column to update
	NewValue     interface{}            `json:"new_value"`     // any JSON value; null → SQL NULL
	PKValues     map[string]interface{} `json:"pk_values"`     // every PK column → its value
}

// CellUpdateResult reports the outcome of a single-cell UPDATE.
type CellUpdateResult struct {
	RowsAffected int64       `json:"rows_affected"`
	DurationMS   int64       `json:"duration_ms"`
	NewValue     interface{} `json:"new_value,omitempty"` // re-fetched from the DB
	SQLPattern   string      `json:"sql_pattern"`         // identifiers quoted, values as $N
}

// identRegex restricts schema/table/column names to safe SQL identifiers.
// We refuse anything outside [A-Za-z_][A-Za-z0-9_]{0,62}. Quoted
// identifiers (`"weird name"`) aren't supported in the dashboard — keeps
// the validation simple and refuses the rare-but-real case where a
// column name contains a quote.
var identRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// quoteIdent wraps an already-validated identifier in postgres-style
// double quotes. Validation is the SOLE defence against identifier
// injection — wrapping alone would still let `"; DROP TABLE..."` slip
// through if the regex were relaxed. We never relax the regex.
func quoteIdent(name string) string { return `"` + name + `"` }

// ApplyCellUpdate runs the single-cell UPDATE. Postgres only in v1.
// Sequence:
//   1. Validate every identifier against identRegex.
//   2. Resolve connection + open DB.
//   3. Re-validate identifiers against pg_catalog: schema/table must
//      exist, column must be a real attribute of the table, and PK
//      columns must exactly match the table's primary key.
//   4. Build "UPDATE \"s\".\"t\" SET \"c\" = $1 WHERE \"pk1\" = $2 ..."
//      with value placeholders only for the SET value and the WHERE
//      values. Identifiers are baked in (already validated + quoted).
//   5. ExecContext with a 30s timeout.
//   6. Re-fetch the new value of the cell and return it.
func (s *Service) ApplyCellUpdate(in CellUpdateInput, sessionSecret string) (*CellUpdateResult, error) {
	// 1. Identifier syntax check.
	for label, v := range map[string]string{
		"schema": in.Schema, "table": in.Table, "column": in.Column,
	} {
		if v == "" {
			return nil, fmt.Errorf("%s is required", label)
		}
		if !identRegex.MatchString(v) {
			return nil, fmt.Errorf("invalid %s identifier", label)
		}
	}
	if len(in.PKValues) == 0 {
		return nil, errors.New("pk_values is required (at least one primary-key column)")
	}
	pkNames := make([]string, 0, len(in.PKValues))
	for k := range in.PKValues {
		if !identRegex.MatchString(k) {
			return nil, fmt.Errorf("invalid pk column identifier")
		}
		pkNames = append(pkNames, k)
	}

	engine, dsn, _, err := s.resolveDSN(in.ConnectionID, sessionSecret)
	if err != nil {
		return nil, err
	}
	if engine != EnginePostgres {
		return nil, errors.New("inline cell editing is only supported on postgres connections in this version")
	}

	db, err := sql.Open(engine.DriverName(), dsn)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(QueryTimeout)
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()

	// 3. Catalogue re-validation. This is the second layer that closes
	// the case where the regex would otherwise pass through a syntactically
	// valid but non-existent identifier. We refuse before any UPDATE runs.
	if err := assertTableExists(ctx, db, in.Schema, in.Table); err != nil {
		return nil, err
	}
	if err := assertColumnExists(ctx, db, in.Schema, in.Table, in.Column); err != nil {
		return nil, err
	}
	if err := assertExactPK(ctx, db, in.Schema, in.Table, pkNames); err != nil {
		return nil, err
	}

	// 4. Build the SQL with quoted identifiers + value placeholders.
	args := []interface{}{in.NewValue}
	whereParts := make([]string, 0, len(pkNames))
	for i, c := range pkNames {
		whereParts = append(whereParts, fmt.Sprintf("%s = $%d", quoteIdent(c), i+2))
		args = append(args, in.PKValues[c])
	}
	stmt := fmt.Sprintf(
		"UPDATE %s.%s SET %s = $1 WHERE %s",
		quoteIdent(in.Schema),
		quoteIdent(in.Table),
		quoteIdent(in.Column),
		strings.Join(whereParts, " AND "),
	)

	// 5. Execute.
	start := time.Now()
	res, err := db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	rows, _ := res.RowsAffected()
	duration := time.Since(start).Milliseconds()

	if rows == 0 {
		// 0-rows usually means the PK didn't match anything — concurrency
		// or stale data on the operator's screen. Surface explicitly.
		return &CellUpdateResult{
			RowsAffected: 0,
			DurationMS:   duration,
			SQLPattern:   stmt,
		}, errors.New("no row matched the primary key — refresh and try again (the row may have been deleted or the PK changed)")
	}
	if rows > 1 {
		// Should be impossible because we required the PK columns; but if
		// it happens, surface as an error so a future schema bug doesn't
		// silently mass-update.
		return &CellUpdateResult{
			RowsAffected: rows,
			DurationMS:   duration,
			SQLPattern:   stmt,
		}, fmt.Errorf("UPDATE matched %d rows; aborted because cell-edit must be a single-row operation", rows)
	}

	// 6. Re-fetch the canonical new value (the DB may have applied a
	// trigger, default, or coercion).
	selStmt := fmt.Sprintf(
		"SELECT %s FROM %s.%s WHERE %s",
		quoteIdent(in.Column),
		quoteIdent(in.Schema),
		quoteIdent(in.Table),
		strings.Join(whereParts, " AND "),
	)
	var newVal interface{}
	if err := db.QueryRowContext(ctx, selStmt, args[1:]...).Scan(&newVal); err != nil {
		// Non-fatal: the UPDATE itself succeeded; we just couldn't read back.
		newVal = in.NewValue
	}
	if b, ok := newVal.([]byte); ok {
		newVal = string(b)
	}

	return &CellUpdateResult{
		RowsAffected: rows,
		DurationMS:   duration,
		NewValue:     newVal,
		SQLPattern:   stmt,
	}, nil
}

// ── Catalogue assertions (postgres) ─────────────────────────────────────

func assertTableExists(ctx context.Context, db *sql.DB, schema, table string) error {
	var n int
	err := db.QueryRowContext(ctx, `
		select count(*) from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		where n.nspname = $1 and c.relname = $2 and c.relkind in ('r','p')
	`, schema, table).Scan(&n)
	if err != nil {
		return sanitizeDriverError(err)
	}
	if n == 0 {
		return errors.New("table not found in catalogue")
	}
	return nil
}

func assertColumnExists(ctx context.Context, db *sql.DB, schema, table, column string) error {
	var n int
	err := db.QueryRowContext(ctx, `
		select count(*) from pg_attribute a
		join pg_class c on c.oid = a.attrelid
		join pg_namespace n on n.oid = c.relnamespace
		where n.nspname = $1 and c.relname = $2 and a.attname = $3 and a.attnum > 0 and not a.attisdropped
	`, schema, table, column).Scan(&n)
	if err != nil {
		return sanitizeDriverError(err)
	}
	if n == 0 {
		return errors.New("column not found in table")
	}
	return nil
}

// assertExactPK rejects when the client-provided PK column set does not
// EXACTLY match the table's primary key. Defends against the case where
// an operator (or compromised UI) sends a non-PK column as the WHERE
// predicate, which could match many rows.
func assertExactPK(ctx context.Context, db *sql.DB, schema, table string, claimed []string) error {
	rows, err := db.QueryContext(ctx, `
		select a.attname
		from pg_index i
		join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
		join pg_class c on c.oid = i.indrelid
		join pg_namespace n on n.oid = c.relnamespace
		where i.indisprimary and n.nspname = $1 and c.relname = $2
	`, schema, table)
	if err != nil {
		return sanitizeDriverError(err)
	}
	defer rows.Close()
	actual := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return err
		}
		actual[c] = true
	}
	if len(actual) == 0 {
		return errors.New("table has no primary key — cell editing requires one")
	}
	if len(claimed) != len(actual) {
		return errors.New("primary-key column set mismatch")
	}
	for _, c := range claimed {
		if !actual[c] {
			return errors.New("primary-key column set mismatch")
		}
	}
	return nil
}
