package dbquery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// QueryResult is the shape returned to the API. Columns are named, rows
// are arrays of values aligned to the column order. Truncated indicates
// the result was capped by MaxResultRows or MaxResultBytes.
type QueryResult struct {
	Columns      []string        `json:"columns"`
	Rows         [][]interface{} `json:"rows"`
	RowsAffected int64           `json:"rows_affected,omitempty"`
	DurationMS   int64           `json:"duration_ms"`
	Truncated    bool            `json:"truncated,omitempty"`
	IsResultSet  bool            `json:"is_result_set"` // true for SELECT, false for DML/DDL
	// Editable, when non-nil, tells the UI it MAY enable inline cell
	// editing on this result. Populated only after a successful single-
	// table SELECT against postgres whose returned columns include the
	// table's complete primary key. Nil for everything else (joins,
	// aggregates, views, mysql, etc.) and the UI must keep cells
	// read-only in that case.
	Editable *EditableMeta `json:"editable,omitempty"`
}

// TestConnection opens a connection, pings, and closes. Returns nil on
// success or a sanitized error on failure (driver errors stripped of
// hostnames, paths, and credentials before reaching the API).
func (s *Service) TestConnection(id, sessionSecret string) error {
	engine, dsn, _, err := s.resolveDSN(id, sessionSecret)
	if err != nil {
		return err
	}
	driver := engine.DriverName()
	if driver == "" {
		return errors.New("driver not registered")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return sanitizeDriverError(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(30 * time.Second)
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return sanitizeDriverError(err)
	}
	return nil
}

// ExecuteQuery runs `query` on the connection identified by `id`. The
// query runs with QueryTimeout context; results are capped at
// MaxResultRows / MaxResultBytes; the connection is closed at the end.
//
// SQL is sent verbatim to the driver. This is by design — the operator
// IS the trusted writer of SQL here. Authorization is the dashboard
// session, not query-shape validation. Audit log records every call.
func (s *Service) ExecuteQuery(id, sessionSecret, query string) (*QueryResult, error) {
	if query == "" {
		return nil, errors.New("query is empty")
	}
	if len(query) > 64*1024 {
		return nil, errors.New("query too large (max 64 KB)")
	}
	engine, dsn, _, err := s.resolveDSN(id, sessionSecret)
	if err != nil {
		return nil, err
	}
	driver := engine.DriverName()
	if driver == "" {
		return nil, errors.New("driver not registered")
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(QueryTimeout)
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()

	start := time.Now()

	// Try as a query with a result set first (SELECT, SHOW, etc.). If
	// the driver reports "no result set" or similar, fall through to Exec.
	rows, err := db.QueryContext(ctx, query)
	if err == nil {
		defer rows.Close()
		result, rerr := readRows(rows)
		if rerr != nil {
			return nil, sanitizeDriverError(rerr)
		}
		result.DurationMS = time.Since(start).Milliseconds()
		result.IsResultSet = true
		// Postgres-only inline-edit metadata. Catalogue lookups are
		// short and run inside the same context; failure to detect just
		// means the UI keeps the result read-only — never blocks the
		// query response.
		if engine == EnginePostgres {
			detCtx, detCancel := context.WithTimeout(context.Background(), 5*time.Second)
			result.Editable = detectEditable(detCtx, db, query, result.Columns)
			detCancel()
		}
		return result, nil
	}

	// Some drivers refuse to QueryContext on a non-SELECT (mysql does
	// for INSERT/UPDATE), others accept it and return zero rows. Detect
	// and fall back to Exec for DML/DDL.
	if isNoRowsErr(err) {
		execRes, eerr := db.ExecContext(ctx, query)
		if eerr != nil {
			return nil, sanitizeDriverError(eerr)
		}
		var n int64
		if v, vErr := execRes.RowsAffected(); vErr == nil {
			n = v
		}
		return &QueryResult{
			Columns:      nil,
			Rows:         nil,
			RowsAffected: n,
			DurationMS:   time.Since(start).Milliseconds(),
			IsResultSet:  false,
		}, nil
	}
	return nil, sanitizeDriverError(err)
}

// readRows scans a sql.Rows up to MaxResultRows / MaxResultBytes, returning
// the result and a Truncated flag if any cap was hit. Values are coerced
// to JSON-safe types: []byte becomes string (assuming UTF-8); time.Time is
// preserved (encoding/json handles it).
func readRows(rows *sql.Rows) (*QueryResult, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &QueryResult{Columns: cols}
	bytesUsed := 0
	for rows.Next() {
		if len(out.Rows) >= MaxResultRows {
			out.Truncated = true
			break
		}
		buf := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range cols {
			ptrs[i] = &buf[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		// Coerce []byte → string, otherwise JSON marshals to base64.
		// Approximate byte size as we go for the byte cap.
		rowBytes := 0
		for i, v := range buf {
			if b, ok := v.([]byte); ok {
				buf[i] = string(b)
				rowBytes += len(b)
			} else if s, ok := v.(string); ok {
				rowBytes += len(s)
			} else {
				rowBytes += 16 // rough overhead per scalar
			}
		}
		bytesUsed += rowBytes
		if bytesUsed > MaxResultBytes {
			out.Truncated = true
			break
		}
		out.Rows = append(out.Rows, buf)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// isNoRowsErr detects the family of errors drivers emit when QueryContext
// is called on a statement that doesn't produce rows. Different drivers
// word this differently, so we match on substrings.
func isNoRowsErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, needle := range []string{
		"no result set",
		"no rows in result set",
		"result set is empty",
		"is not a query",
	} {
		if containsCI(s, needle) {
			return true
		}
	}
	return false
}

// sanitizeDriverError converts a driver error into a generic, log-safe
// string. Drivers like lib/pq embed the host/user/db in error text;
// surfacing those to the API caller would leak metadata. We keep the
// SQLSTATE / errno when available because that's actionable; everything
// else is replaced.
func sanitizeDriverError(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	// Postgres lib/pq formats: `pq: <message> (SQLSTATE XXXXX)`. Keep
	// SQLSTATE if present.
	if idx := indexOfCI(s, "sqlstate "); idx >= 0 {
		end := idx + len("sqlstate ")
		if end+5 <= len(s) {
			code := s[end : end+5]
			return fmt.Errorf("database error (SQLSTATE %s)", code)
		}
	}
	// MySQL: `Error 1064 (42000): ...`
	if idx := indexOfCI(s, "error "); idx == 0 {
		// Take the next number after "Error "
		rest := s[len("Error "):]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			return fmt.Errorf("database error (errno %s)", rest[:end])
		}
	}
	// Generic fallback. Don't echo `s` — could contain creds.
	return errors.New("database error")
}

// containsCI / indexOfCI: case-insensitive helpers. Avoid importing
// strings throughout to keep the package's import block tight.
func containsCI(haystack, needle string) bool { return indexOfCI(haystack, needle) >= 0 }

func indexOfCI(haystack, needle string) int {
	if needle == "" {
		return 0
	}
	hl, nl := len(haystack), len(needle)
	if nl > hl {
		return -1
	}
outer:
	for i := 0; i+nl <= hl; i++ {
		for j := 0; j < nl; j++ {
			a := haystack[i+j]
			b := needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				continue outer
			}
		}
		return i
	}
	return -1
}
