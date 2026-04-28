package dbquery

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// normalizeDSN validates and lightly hardens the operator-supplied DSN
// before storing it. We do NOT rewrite the DSN destructively — operators
// might genuinely need TLS off for a local container — but we DO refuse
// shapes that don't parse, and inject a TLS preference when one is
// missing entirely (and document the choice).
//
// Two engines, two DSN shapes:
//
//   postgres: URI form `postgres://user:pass@host:port/db?sslmode=...`
//             or libpq keyword form `host=... port=... user=... ...`.
//             The `lib/pq` driver accepts both.
//
//   mysql:    DSN form `user:pass@tcp(host:port)/db?param=value` per
//             go-sql-driver/mysql convention.
func normalizeDSN(engine Engine, dsn string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "", errors.New("dsn is empty")
	}
	switch engine {
	case EnginePostgres:
		return normalizePostgresDSN(dsn)
	case EngineMySQL:
		return normalizeMySQLDSN(dsn)
	}
	return "", fmt.Errorf("unsupported engine %q", engine)
}

func normalizePostgresDSN(dsn string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid postgres URL")
		}
		q := u.Query()
		// If sslmode wasn't specified, lean toward TLS but degrade gracefully
		// — `prefer` tries TLS first and falls back to plaintext if the
		// server doesn't speak it. Operators wanting strict TLS should set
		// `sslmode=require` (or verify-full) explicitly.
		if q.Get("sslmode") == "" {
			q.Set("sslmode", "prefer")
			u.RawQuery = q.Encode()
		}
		return u.String(), nil
	}
	// libpq keyword form: validate by checking it has at least one `=`.
	if !strings.Contains(dsn, "=") {
		return "", errors.New("postgres DSN must be a postgres:// URL or 'key=value' libpq form")
	}
	if !strings.Contains(dsn, "sslmode=") {
		dsn = strings.TrimSpace(dsn) + " sslmode=prefer"
	}
	return dsn, nil
}

func normalizeMySQLDSN(dsn string) (string, error) {
	// Format: [user[:pass]@][protocol[(addr)]]/dbname[?params]
	// We don't dissect the user:pass section because of allowed symbols.
	// Just verify a `/` exists (separates host section from db) and
	// nudge `?tls=preferred` if no tls= param is present.
	slash := strings.LastIndex(dsn, "/")
	if slash < 0 {
		return "", errors.New("mysql DSN must contain '/<dbname>'")
	}
	if !strings.Contains(dsn, "tls=") {
		if strings.Contains(dsn, "?") {
			dsn = dsn + "&tls=preferred"
		} else {
			dsn = dsn + "?tls=preferred"
		}
	}
	// Ensure parseTime so DATE/DATETIME come back as time.Time, not raw bytes.
	if !strings.Contains(dsn, "parseTime=") {
		if strings.Contains(dsn, "?") {
			dsn = dsn + "&parseTime=true"
		} else {
			dsn = dsn + "?parseTime=true"
		}
	}
	return dsn, nil
}

// SafeDescribeDSN returns an operator-friendly summary of the DSN with
// the password redacted. Used by audit log + UI when the operator wants
// to see "where am I connected to" without exposing the credential.
func SafeDescribeDSN(engine Engine, dsn string) string {
	switch engine {
	case EnginePostgres:
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, err := url.Parse(dsn)
			if err != nil {
				return "postgres://?"
			}
			if u.User != nil {
				u.User = url.UserPassword(u.User.Username(), "***")
			}
			return u.Redacted()
		}
		// libpq keyword form: redact password=...
		out := []string{}
		for _, kv := range strings.Fields(dsn) {
			if strings.HasPrefix(strings.ToLower(kv), "password=") {
				out = append(out, "password=***")
			} else {
				out = append(out, kv)
			}
		}
		return strings.Join(out, " ")
	case EngineMySQL:
		// Redact between `:` (after user) and `@`
		atIdx := strings.LastIndex(dsn, "@")
		if atIdx < 0 {
			return dsn
		}
		userSection := dsn[:atIdx]
		colonIdx := strings.Index(userSection, ":")
		if colonIdx < 0 {
			return dsn
		}
		return userSection[:colonIdx+1] + "***" + dsn[atIdx:]
	}
	return "(redacted)"
}
