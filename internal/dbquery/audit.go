package dbquery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	auditLogPath = "/var/log/serverpilot-dbquery-audit.log"
	auditLogMode = 0o640
)

// AuditEntry is the on-disk shape (one JSON object per line). The query
// is NEVER stored in the clear — only its SHA-256 — because queries
// commonly contain credential literals or PII inside WHERE clauses.
// The actor + connection + duration + outcome are all the forensics a
// later investigator needs.
type AuditEntry struct {
	Timestamp    string `json:"timestamp"`
	Actor        string `json:"actor"`
	ConnectionID string `json:"connection_id"`
	ConnName     string `json:"connection_name,omitempty"`
	Engine       Engine `json:"engine,omitempty"`
	QuerySHA256  string `json:"query_sha256"`
	QueryBytes   int    `json:"query_bytes"`
	Action       string `json:"action"` // "test" | "execute"
	Result       string `json:"result"` // "ok" | "error" | "truncated"
	DurationMS   int64  `json:"duration_ms,omitempty"`
	RowsReturned int    `json:"rows_returned,omitempty"`
	RowsAffected int64  `json:"rows_affected,omitempty"`
	Error        string `json:"error,omitempty"` // already sanitized
}

var (
	auditMu     sync.Mutex
	auditFile   *os.File
	auditOpened bool
)

// Audit appends a structured entry. Failures to write the audit log are
// reported to stderr (which goes to journald) but never block the
// caller — a logging outage cannot kill query execution.
func Audit(entry AuditEntry) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	entry.Actor = sanitize(entry.Actor)
	entry.ConnName = sanitize(entry.ConnName)
	entry.Error = sanitize(entry.Error)

	auditMu.Lock()
	defer auditMu.Unlock()
	if !auditOpened {
		if err := openAuditLog(); err != nil {
			fmt.Fprintf(os.Stderr, "dbquery audit: cannot open log: %v\n", err)
			return
		}
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = auditFile.Write(data)
}

func openAuditLog() error {
	if err := os.MkdirAll("/var/log", 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, auditLogMode)
	if err != nil {
		return err
	}
	_ = f.Chmod(auditLogMode)
	auditFile = f
	auditOpened = true
	return nil
}

// HashQuery returns the SHA-256 of the query as a hex string. Used by
// the audit logger so the log shows _what_ ran without leaking literals.
func HashQuery(q string) string {
	h := sha256.Sum256([]byte(q))
	return hex.EncodeToString(h[:])
}

// sanitize strips control characters and caps length. Defends against
// log-injection (CWE-117) — actor and conn name can flow from operator
// input upstream of the audit logger.
func sanitize(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// AuditTail reads the last `limit` audit entries, newest last. Used by
// the dashboard's audit viewer.
func AuditTail(limit int) ([]AuditEntry, error) {
	auditMu.Lock()
	defer auditMu.Unlock()
	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	start := 0
	if len(lines) > limit+1 {
		start = len(lines) - limit - 1
	}
	out := make([]AuditEntry, 0, limit)
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
