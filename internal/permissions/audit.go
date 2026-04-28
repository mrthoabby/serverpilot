package permissions

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// auditLogPath is root-owned and not configurable via the UI. Hardcoded.
// Mode 0640 so the local `adm` group can read it for log shipping while
// non-privileged users cannot.
const (
	auditLogDir  = "/var/log"
	auditLogFile = "/var/log/serverpilot-permissions-audit.log"
	auditLogMode = 0o640
)

const (
	auditScopeFS      = "filesystem"
	auditScopeGroup   = "group"
	auditScopeSudoers = "sudoers"
)

// AuditEntry is the on-disk shape (one JSON object per line). Field names
// are stable — log parsers in production WILL depend on them. Add new
// fields, never rename or remove.
type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	Actor       string `json:"actor"`        // dashboard admin username
	Action      string `json:"action"`       // fs.grant, fs.revoke, group.grant, group.revoke, sudoers.grant, sudoers.revoke
	Scope       string `json:"scope"`        // filesystem | group | sudoers
	TargetUser  string `json:"target_user"`
	TargetApp   string `json:"target_app,omitempty"` // managed app, or "" for sudoers
	Detail      string `json:"detail,omitempty"`     // level for FS, capability slug for sudoers/group
	Result      string `json:"result"`               // ok | ok-noop | error | validation_failed | install_failed
	Error       string `json:"error,omitempty"`      // sanitized error message (NEVER raw stderr)
}

var (
	auditMu     sync.Mutex
	auditFile   *os.File
	auditOpened bool
)

// audit appends one structured entry to the audit log. The log is
// append-only by virtue of how we open it (O_APPEND); on POSIX, concurrent
// appends from the same process are atomic for writes shorter than
// PIPE_BUF (4096 bytes), which our entries always are.
//
// We deliberately do NOT include raw error.Error() — exec stderr can leak
// file paths, env vars, account hints. Errors are normalised through
// FormatExecError before they reach the audit record.
func (s *Service) audit(actor, action, scope, targetUser, targetApp, detail, result string, errSrc error) error {
	entry := AuditEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Actor:      sanitizeAuditField(actor),
		Action:     action,
		Scope:      scope,
		TargetUser: sanitizeAuditField(targetUser),
		TargetApp:  sanitizeAuditField(targetApp),
		Detail:     sanitizeAuditField(detail),
		Result:     result,
	}
	if errSrc != nil {
		// Only log a generic, redacted form of the underlying error.
		entry.Error = sanitizeAuditField(redactError(errSrc))
	}
	return appendAuditEntry(entry)
}

func appendAuditEntry(entry AuditEntry) error {
	auditMu.Lock()
	defer auditMu.Unlock()
	if !auditOpened {
		if err := openAuditLog(); err != nil {
			// Failure to open the audit log MUST NOT block the operation —
			// a logging outage cannot leave the dashboard unusable. We log
			// the open failure to stderr (which goes to journald) and
			// proceed. The grant/revoke itself still ran; the gap is
			// visible in the journal.
			fmt.Fprintf(os.Stderr, "audit: cannot open log: %v\n", err)
			return nil
		}
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := auditFile.Write(data); err != nil {
		return err
	}
	return nil
}

func openAuditLog() error {
	if err := os.MkdirAll(auditLogDir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, auditLogMode)
	if err != nil {
		return err
	}
	// Tighten permissions to the canonical mode in case the file existed
	// with a wider mode.
	_ = f.Chmod(auditLogMode)
	auditFile = f
	auditOpened = true
	return nil
}

// sanitizeAuditField removes control characters that could be used to
// inject fake log lines (CWE-117 — log injection). Caps the length at 256
// bytes to avoid a single field eating the whole log line.
func sanitizeAuditField(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		// Allow printable ASCII + extended UTF-8 letters; drop control codes.
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

// redactError extracts a non-leaky string from an error. We rely on
// FormatExecError having already converted exec.ExitError into
// "<stage> failed [with exit code N]"; for other error sources we just
// take the .Error() text and sanitize it.
func redactError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// AuditTail reads up to `limit` recent entries (newest last) from the
// audit log. Used by the dashboard's audit viewer.
//
// Implementation note: we read the whole file because operators want
// deterministic tail behaviour across rotations and because the file is
// small (< 1 MB in typical deployments). For larger volumes a future
// improvement is to seek from the end. Until then, cap reading at 4 MB
// to keep memory bounded.
func (s *Service) AuditTail(limit int) ([]AuditEntry, error) {
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.Open(auditLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	defer f.Close()

	const maxRead = 4 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil {
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
