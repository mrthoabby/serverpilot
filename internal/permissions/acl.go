package permissions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// managedAppRoot is the only base directory under which ACL grants are
// allowed. Hardcoded — never derived from user input.
const managedAppRoot = "/opt"

// FSGrant describes a single user→app→level mapping reported by GetACL.
type FSGrant struct {
	Username string `json:"username"`
	Level    Level  `json:"level"`
}

// GrantFS applies a filesystem ACL grant for `username` on /opt/<app>. The
// previous grant for that user (if any) is revoked first so transitions
// are atomic from the caller's point of view (no intermediate "both
// levels" state).
//
// Security:
//   - The path /opt/<app> is built ONLY from the validated app name. We
//     additionally check that the resolved leaf is not a symlink — a local
//     attacker who could create /opt/<app> as a symlink to / would
//     otherwise have us setfacl the entire root filesystem.
//   - exec.Command receives separate argv entries; "--" terminates option
//     parsing so a path that begins with "-" cannot be re-interpreted as a
//     setfacl flag.
//   - The level is an enum, mapped to a fixed setfacl spec — never a
//     concatenated string from input.
//   - No `chmod` and no `chown` is ever issued by this package.
func (s *Service) GrantFS(actor, username, app string, level Level) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if err := s.validateManagedApp(app); err != nil {
		return err
	}
	if !level.Valid() {
		return ErrInvalidLevel
	}

	dir := filepath.Join(managedAppRoot, app)
	if err := assertSafeManagedAppDir(dir); err != nil {
		return err
	}

	if !s.deps.HasACL(managedAppRoot) {
		return ErrACLNotSupported
	}

	// Always revoke first so the spec for the new level is the only spec
	// for this user — clean transition between read↔write.
	if err := runSetFACLRemove(dir, username); err != nil {
		return err
	}

	if level == LevelNone {
		return s.audit(actor, "fs.revoke", auditScopeFS, username, app, "", "ok", nil)
	}

	spec, defSpec := aclSpecForLevel(username, level)
	if spec != "" {
		if err := runSetFACL(dir, "-R", "-m", spec); err != nil {
			_ = s.audit(actor, "fs.grant", auditScopeFS, username, app, string(level), "error", err)
			return FormatExecError("setfacl access", err)
		}
	}
	if defSpec != "" {
		if err := runSetFACL(dir, "-R", "-d", "-m", defSpec); err != nil {
			// Best-effort rollback so we don't leave half-applied state.
			_ = runSetFACLRemove(dir, username)
			_ = s.audit(actor, "fs.grant", auditScopeFS, username, app, string(level), "error", err)
			return FormatExecError("setfacl default", err)
		}
	}

	return s.audit(actor, "fs.grant", auditScopeFS, username, app, string(level), "ok", nil)
}

// RevokeFS removes the user's ACL entry from /opt/<app>. Idempotent: if no
// entry exists for the user, the call still succeeds and the audit log
// records the no-op.
func (s *Service) RevokeFS(actor, username, app string) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if err := s.validateManagedApp(app); err != nil {
		return err
	}
	dir := filepath.Join(managedAppRoot, app)
	if err := assertSafeManagedAppDir(dir); err != nil {
		return err
	}
	if !s.deps.HasACL(managedAppRoot) {
		return ErrACLNotSupported
	}

	if err := runSetFACLRemove(dir, username); err != nil {
		_ = s.audit(actor, "fs.revoke", auditScopeFS, username, app, "", "error", err)
		return FormatExecError("setfacl revoke", err)
	}
	return s.audit(actor, "fs.revoke", auditScopeFS, username, app, "", "ok", nil)
}

// ListFSGrants returns the live ACL state for /opt/<app>. The displayed
// state is real (parsed from getfacl) — the registry is only consulted for
// drift detection, NOT for the displayed value.
func (s *Service) ListFSGrants(app string) ([]FSGrant, error) {
	if err := s.validateManagedApp(app); err != nil {
		return nil, err
	}
	dir := filepath.Join(managedAppRoot, app)
	if err := assertSafeManagedAppDir(dir); err != nil {
		return nil, err
	}
	if !s.deps.HasACL(managedAppRoot) {
		return nil, ErrACLNotSupported
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	getfacl := getfaclPath()
	if getfacl == "" {
		return nil, ErrACLNotSupported
	}
	out, err := exec.CommandContext(ctx, getfacl, "-c", "--", dir).Output()
	if err != nil {
		return nil, FormatExecError("getfacl", err)
	}
	return parseGetFACL(string(out))
}

// assertSafeManagedAppDir refuses to operate on a /opt/<app> path that:
//   - Falls outside /opt/ after canonicalisation (defence against managed
//     app names that pass the regex but somehow contain a "..").
//   - Is a symlink (would cause setfacl to operate on the target instead).
func assertSafeManagedAppDir(dir string) error {
	clean := filepath.Clean(dir)
	rel, err := filepath.Rel(managedAppRoot, clean)
	if err != nil || strings.HasPrefix(rel, "..") || strings.ContainsRune(rel, filepath.Separator) {
		return fmt.Errorf("path is outside %s", managedAppRoot)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("managed app directory does not exist")
		}
		return fmt.Errorf("cannot stat managed app directory")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to operate on a symlinked managed app directory")
	}
	if !info.IsDir() {
		return fmt.Errorf("managed app path is not a directory")
	}
	return nil
}

// aclSpecForLevel maps a Level enum to (access-spec, default-spec) strings.
//
// We use the mask form `r-X` / `rwX` (capital X) so:
//   - directories get the +x bit needed for traversal,
//   - regular files only get +x if they were already executable
//     (avoids accidentally marking text files as executables).
//
// The default ACL ensures newly created files inside /opt/<app> inherit
// the same per-user grant.
func aclSpecForLevel(username string, level Level) (access, def string) {
	switch level {
	case LevelRead:
		return "u:" + username + ":r-X", "u:" + username + ":r-X"
	case LevelWrite:
		return "u:" + username + ":rwX", "u:" + username + ":rwX"
	}
	return "", ""
}

// runSetFACL is the single chokepoint for setfacl invocations. Every call
// goes through here so the security review only has to verify one path.
//
// The "-h" / "--no-dereference" flag is NOT used here because we have
// already refused to operate on a symlinked top, AND -R combined with
// --no-dereference is incompatible (setfacl errors out). The recursive
// walk follows symlinks WITHIN the tree, which is the documented
// behaviour and matches what an operator expects when granting access to
// "the contents of /opt/<app>".
func runSetFACL(dir string, args ...string) error {
	setfacl := setfaclPath()
	if setfacl == "" {
		return ErrACLNotSupported
	}
	full := append([]string{}, args...)
	full = append(full, "--", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, setfacl, full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Do not bubble stderr into API errors — see FormatExecError.
		_ = out
		return err
	}
	return nil
}

// runSetFACLRemove removes both the access and default ACL entries for a
// specific user from `dir` (recursive). If the user has no entry at all,
// setfacl exits 0 in modern util-linux releases; older versions exit 1
// with "Invalid argument" — we treat that as success too (idempotent
// revoke).
func runSetFACLRemove(dir, username string) error {
	setfacl := setfaclPath()
	if setfacl == "" {
		return ErrACLNotSupported
	}
	full := []string{"-R", "-x", "u:" + username, "-x", "d:u:" + username, "--", dir}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, setfacl, full...).CombinedOutput()
	if err == nil {
		return nil
	}
	combined := strings.ToLower(string(out))
	if strings.Contains(combined, "invalid argument") || strings.Contains(combined, "no such") {
		return nil
	}
	return err
}

// parseGetFACL extracts per-user ACL entries from `getfacl -c <dir>` output.
// The format is one ACL entry per line; we only care about lines that
// begin with "user:" AND have a non-empty username (the line "user::rwx"
// describes the file owner, not a per-user ACL grant).
//
// Effective masks (lines like "user:alice:rwx\t#effective:r--") are honored
// — we report the effective permissions, not the requested ones. Otherwise
// the UI would lie when the mask narrows the effective grant.
func parseGetFACL(out string) ([]FSGrant, error) {
	var grants []FSGrant
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "user:alice:rwx" or "user:alice:rwx\t#effective:r--"
		if !strings.HasPrefix(line, "user:") {
			continue
		}
		// Skip the "user::xxx" owner line.
		if strings.HasPrefix(line, "user::") {
			continue
		}
		// Split off any effective annotation.
		main := line
		if i := strings.IndexByte(line, '#'); i >= 0 {
			main = strings.TrimSpace(line[:i])
		}
		parts := strings.SplitN(main, ":", 3)
		if len(parts) != 3 {
			continue
		}
		user := parts[1]
		mode := parts[2]

		// Determine effective mode if an "#effective:" hint is present.
		effective := mode
		if i := strings.Index(line, "#effective:"); i >= 0 {
			effective = strings.TrimSpace(line[i+len("#effective:"):])
		}

		// Map the effective bits to our enum. Treat "r-X" and "r--" as read,
		// "rw-" / "rwx" / "rwX" as write, "---" as none.
		level := LevelNone
		switch {
		case strings.Contains(effective, "w"):
			level = LevelWrite
		case strings.ContainsAny(effective, "rX"):
			level = LevelRead
		}
		grants = append(grants, FSGrant{Username: user, Level: level})
	}
	return grants, nil
}
