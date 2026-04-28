package permissions

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// sudoersDir is where Debian-family distros place drop-in sudoers
// fragments. The main /etc/sudoers `#includedir /etc/sudoers.d` directive
// loads every file in this directory whose name does NOT contain a dot or
// end with ~. Hardcoded; never derived from input.
const sudoersDir = "/etc/sudoers.d"

// sudoersFilePrefix is the static prefix every fragment we install starts
// with, so a single `ls /etc/sudoers.d/serverpilot-*` shows everything we
// own. We avoid dots and `~` in the suffix because sudoers ignores those.
const sudoersFilePrefix = "serverpilot-"

// fragmentNameRegex describes the full filename. The username and rule
// names are validated separately, but we double-check the assembled name
// here to catch any future bug that builds the path with a tainted value.
var fragmentNameRegex = regexp.MustCompile(`^serverpilot-[a-z][a-z0-9_-]{0,31}-[a-z][a-z0-9-]{0,32}$`)

// sudoersRuleRegex matches the rule slug used in the URL/API. Strict
// alphanumeric+hyphen so it can be safely interpolated into a filename and
// into the sudoers comment line without quoting concerns.
var sudoersRuleRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// SudoersGrant reports a single user→rule installation. The rule slug
// matches the static template (e.g. "nginx-reload"), not arbitrary text.
type SudoersGrant struct {
	Username string `json:"username"`
	Rule     string `json:"rule"`
	Command  string `json:"command"`
	Active   bool   `json:"active"`
}

// GrantSudoers installs a sudoers fragment for username×rule. The set of
// possible rules is the union of every system app template's rules (see
// templates.go); rule slugs the dashboard does not know are rejected.
//
// Defences (in order applied):
//   1. validateUsername — regex + managed-user check.
//   2. sudoersRuleRegex — strict slug; refuses anything that could be a
//      filename traversal vector.
//   3. Lookup the rule in the static template map — refuses unknown rules.
//   4. Compose the fragment with a hardcoded `Cmnd_Alias` style line that
//      includes the EXACT command from the template, never user input.
//   5. Write to a CreateTemp inside /etc/sudoers.d (so the rename is
//      genuinely atomic on the same FS), chmod 0440, sync.
//   6. visudo -c -f <tmp> — refuse to install if visudo rejects it. THIS
//      IS NOT OPTIONAL. A bad sudoers can lock out every operator.
//   7. Atomic rename to the final path.
//   8. Audit log entry.
func (s *Service) GrantSudoers(actor, username, ruleSlug string) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if !sudoersRuleRegex.MatchString(ruleSlug) {
		return fmt.Errorf("invalid rule slug")
	}
	rule, ok := lookupSudoersRule(ruleSlug)
	if !ok {
		return ErrInvalidCapability
	}
	if !s.deps.HasVisudo() {
		return errors.New("visudo not available — refusing to install sudoers fragment")
	}

	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		return fmt.Errorf("cannot ensure sudoers.d exists")
	}

	fragmentName := buildFragmentName(username, ruleSlug)
	if !fragmentNameRegex.MatchString(fragmentName) {
		return errors.New("internal: assembled sudoers fragment name failed validation")
	}
	finalPath := filepath.Join(sudoersDir, fragmentName)

	body := buildSudoersBody(username, rule)

	tmp, err := os.CreateTemp(sudoersDir, ".serverpilot-sudoers-*")
	if err != nil {
		return fmt.Errorf("cannot create sudoers temp file")
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	defer cleanup()

	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write sudoers temp file")
	}
	// Mode MUST be 0440 — sudoers refuses to load anything more permissive.
	if err := tmp.Chmod(0o440); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot chmod sudoers temp file")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot fsync sudoers temp file")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot close sudoers temp file")
	}

	// visudo -c -f reads the fragment as if it were a sudoers file and
	// checks syntax + privilege escalation against the loaded rules. Refuse
	// installation if visudo fails — better to error here than to break
	// sudo system-wide.
	visudoCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	visudo := visudoPath()
	if visudo == "" {
		return errors.New("visudo not available")
	}
	if err := exec.CommandContext(visudoCtx, visudo, "-c", "-f", tmpPath).Run(); err != nil {
		_ = s.audit(actor, "sudoers.grant", auditScopeSudoers, username, "", ruleSlug, "validation_failed", err)
		return errors.New("sudoers fragment failed visudo validation")
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = s.audit(actor, "sudoers.grant", auditScopeSudoers, username, "", ruleSlug, "install_failed", err)
		return fmt.Errorf("cannot install sudoers fragment")
	}
	// Cleanup defer is now a no-op since the temp file moved.
	cleanup = func() {}

	return s.audit(actor, "sudoers.grant", auditScopeSudoers, username, "", ruleSlug, "ok", nil)
}

// RevokeSudoers removes the user×rule fragment. Idempotent — missing file
// is treated as success and recorded as such in the audit log.
func (s *Service) RevokeSudoers(actor, username, ruleSlug string) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if !sudoersRuleRegex.MatchString(ruleSlug) {
		return fmt.Errorf("invalid rule slug")
	}
	if _, ok := lookupSudoersRule(ruleSlug); !ok {
		return ErrInvalidCapability
	}

	finalPath := filepath.Join(sudoersDir, buildFragmentName(username, ruleSlug))
	if err := os.Remove(finalPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s.audit(actor, "sudoers.revoke", auditScopeSudoers, username, "", ruleSlug, "ok-noop", nil)
		}
		_ = s.audit(actor, "sudoers.revoke", auditScopeSudoers, username, "", ruleSlug, "error", err)
		return fmt.Errorf("cannot remove sudoers fragment")
	}
	return s.audit(actor, "sudoers.revoke", auditScopeSudoers, username, "", ruleSlug, "ok", nil)
}

// ListSudoersGrants enumerates the live state by reading /etc/sudoers.d/.
// The displayed value is real, not declared.
func (s *Service) ListSudoersGrants() ([]SudoersGrant, error) {
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		return nil, fmt.Errorf("cannot read sudoers.d")
	}
	entries, err := os.ReadDir(sudoersDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read sudoers.d")
	}

	var grants []SudoersGrant
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, sudoersFilePrefix) {
			continue
		}
		// Refuse to include filenames that contain dots or `~` because
		// sudoers ignores them anyway and they cannot be ours.
		if strings.ContainsAny(name, ".~") {
			continue
		}
		// Only files we own match the regex.
		if !fragmentNameRegex.MatchString(name) {
			continue
		}
		username, ruleSlug, ok := splitFragmentName(name)
		if !ok {
			continue
		}
		rule, ok := lookupSudoersRule(ruleSlug)
		if !ok {
			continue
		}
		grants = append(grants, SudoersGrant{
			Username: username,
			Rule:     ruleSlug,
			Command:  rule.Command,
			Active:   true,
		})
	}
	return grants, nil
}

// HasSudoersGrant returns true iff the named fragment exists. Used by the
// UI to render the toggle state.
func (s *Service) HasSudoersGrant(username, ruleSlug string) (bool, error) {
	if err := s.validateUsername(username); err != nil {
		return false, err
	}
	if !sudoersRuleRegex.MatchString(ruleSlug) {
		return false, fmt.Errorf("invalid rule slug")
	}
	finalPath := filepath.Join(sudoersDir, buildFragmentName(username, ruleSlug))
	_, err := os.Stat(finalPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// buildFragmentName composes the file name from validated parts.
func buildFragmentName(username, ruleSlug string) string {
	return sudoersFilePrefix + username + "-" + ruleSlug
}

// splitFragmentName reverses buildFragmentName. Returns ok=false on any
// shape mismatch.
func splitFragmentName(name string) (username, ruleSlug string, ok bool) {
	if !strings.HasPrefix(name, sudoersFilePrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, sudoersFilePrefix)
	// The rule slug is the LAST hyphen-separated suffix that is itself a
	// known rule. We can't simply split at the last hyphen because rule
	// slugs themselves contain hyphens (e.g. "nginx-reload"). Iterate.
	for i := 0; i < len(rest); i++ {
		if rest[i] != '-' {
			continue
		}
		candidateUser := rest[:i]
		candidateRule := rest[i+1:]
		if !usernameRegex.MatchString(candidateUser) {
			continue
		}
		if !sudoersRuleRegex.MatchString(candidateRule) {
			continue
		}
		if _, known := lookupSudoersRule(candidateRule); known {
			return candidateUser, candidateRule, true
		}
	}
	return "", "", false
}

// buildSudoersBody assembles the fragment content. Every dynamic part is
// already validated (username regex; rule.Command is hardcoded in
// templates.go). The header makes it obvious where the file came from so
// an operator inspecting /etc/sudoers.d/ does not have to grep the source.
func buildSudoersBody(username string, rule SudoersRule) string {
	var b strings.Builder
	b.WriteString("# Managed by ServerPilot. Do not edit by hand.\n")
	b.WriteString("# Rule: " + rule.Slug + " — " + rule.Description + "\n")
	b.WriteString(username + " ALL=(root) NOPASSWD: " + rule.Command + "\n")
	return b.String()
}
