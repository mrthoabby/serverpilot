package permissions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// allowedGroups is the closed allowlist of groups the dashboard may modify.
// Adding a group here is a deliberate security decision — group membership
// always carries a real-world capability, and "docker" in particular is
// equivalent to root (users in `docker` can mount / inside a container).
//
// Hardcoded paths and groups; never derived from user input.
var allowedGroups = map[string]groupMeta{
	"docker": {
		Description: "Run docker commands without sudo",
		Dangerous:   true,
		Warning:     "Members of the docker group can effectively become root by mounting / inside a container.",
	},
}

// Forbidden groups never appear in the allowlist. This map is used as a
// belt-and-suspenders guard so a future maintainer who edits allowedGroups
// in a hurry cannot accidentally add one of these.
var forbiddenGroups = map[string]bool{
	"sudo":   true,
	"wheel":  true,
	"admin":  true,
	"adm":    true,
	"root":   true,
	"shadow": true,
	"disk":   true,
}

type groupMeta struct {
	Description string
	Dangerous   bool
	Warning     string
}

// groupNameRegex is what useradd / groupadd themselves accept on Debian
// derivatives. Refuses leading "-" (which gpasswd would parse as a flag),
// shell metacharacters, or anything that could escape the argv slot.
var groupNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// GroupGrant reports a single user→group membership. Used by the listing
// endpoint that shows the live state.
type GroupGrant struct {
	Username string `json:"username"`
	Group    string `json:"group"`
	Member   bool   `json:"member"`
}

// GrantGroup adds `username` to `group`. The group MUST be in the
// allowlist; passing any other value returns an error without invoking
// gpasswd.
func (s *Service) GrantGroup(actor, username, group string) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if err := validateGroupName(group); err != nil {
		return err
	}
	if _, ok := allowedGroups[group]; !ok {
		return fmt.Errorf("group %q is not in the allowlist — refusing to grant", group)
	}
	gpasswdResolved := gpasswdPath()
	if gpasswdResolved == "" {
		return errors.New("gpasswd not available")
	}

	// gpasswd syntax: `gpasswd -a USER GROUP` where `-a` consumes the next
	// argv slot as USER. The "--" end-of-options marker MUST come AFTER
	// USER (between USER and GROUP) — placing it between -a and USER
	// makes gpasswd treat "--" as the username and fail with exit code 3.
	//
	// Even though both `username` and `group` are pre-validated against
	// usernameRegex / groupNameRegex (neither can start with "-"), keeping
	// the "--" between USER and GROUP is correct defense-in-depth: if a
	// future change loosens the group regex, GROUP cannot be re-interpreted
	// as a flag.
	//
	// gpasswd -a is idempotent: if the user is already in the group it
	// emits a notice but exits 0. We rely on that — the dashboard treats
	// "grant" as desired-state.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpasswdResolved, "-a", username, "--", group)
	if err := cmd.Run(); err != nil {
		_ = s.audit(actor, "group.grant", auditScopeGroup, username, group, "", "error", err)
		return FormatExecError("gpasswd add", err)
	}
	return s.audit(actor, "group.grant", auditScopeGroup, username, group, "", "ok", nil)
}

// RevokeGroup removes `username` from `group`. Idempotent — if the user is
// not a member, gpasswd -d emits a notice and exits 0 on modern releases;
// older releases exit 3, which we treat as success.
//
// Important UX note for the caller: removing a user from a group does NOT
// affect their currently active sessions. Group membership is loaded at
// login by PAM. The dashboard MUST surface this in the revoke confirmation
// so the operator knows to terminate the user's open SSH sessions if the
// goal is to cut off access immediately.
func (s *Service) RevokeGroup(actor, username, group string) error {
	if err := s.validateUsername(username); err != nil {
		return err
	}
	if err := validateGroupName(group); err != nil {
		return err
	}
	// Note: even on revoke we keep the allowlist check. The package will
	// never modify membership in groups outside our control.
	if _, ok := allowedGroups[group]; !ok {
		return fmt.Errorf("group %q is not in the allowlist", group)
	}
	gpasswdResolved := gpasswdPath()
	if gpasswdResolved == "" {
		return errors.New("gpasswd not available")
	}

	// Same arg-order rule as GrantGroup: `--` MUST sit between USER and GROUP.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpasswdResolved, "-d", username, "--", group)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// gpasswd exits 3 when the user is not a member. Treat as success.
		if strings.Contains(strings.ToLower(string(out)), "is not a member") {
			return s.audit(actor, "group.revoke", auditScopeGroup, username, group, "", "ok-noop", nil)
		}
		_ = s.audit(actor, "group.revoke", auditScopeGroup, username, group, "", "error", err)
		return FormatExecError("gpasswd delete", err)
	}
	return s.audit(actor, "group.revoke", auditScopeGroup, username, group, "", "ok", nil)
}

// IsMember returns true iff `username` is currently in `group` (per
// /etc/group; supplementary group lookup via getent for nss-aware sources).
func (s *Service) IsMember(username, group string) (bool, error) {
	if err := s.validateUsername(username); err != nil {
		return false, err
	}
	if err := validateGroupName(group); err != nil {
		return false, err
	}
	return readGroupMembership(group, username)
}

// AllowedGroupsList returns metadata for the groups the dashboard may
// modify. Used by the UI to render the toggle and show warnings.
func AllowedGroupsList() map[string]struct {
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
	Warning     string `json:"warning,omitempty"`
} {
	out := make(map[string]struct {
		Description string `json:"description"`
		Dangerous   bool   `json:"dangerous"`
		Warning     string `json:"warning,omitempty"`
	})
	for k, v := range allowedGroups {
		out[k] = struct {
			Description string `json:"description"`
			Dangerous   bool   `json:"dangerous"`
			Warning     string `json:"warning,omitempty"`
		}{Description: v.Description, Dangerous: v.Dangerous, Warning: v.Warning}
	}
	return out
}

// validateGroupName enforces the regex AND refuses any forbidden name.
func validateGroupName(g string) error {
	if !groupNameRegex.MatchString(g) {
		return fmt.Errorf("invalid group name")
	}
	if forbiddenGroups[g] {
		return fmt.Errorf("group %q is forbidden by policy", g)
	}
	return nil
}

// readGroupMembership scans /etc/group directly. We do NOT shell out to
// `getent group <name>` because that would parse arbitrary NSS modules,
// which on a misconfigured host can hit network services and time out.
// /etc/group is sufficient for ServerPilot-managed groups (docker, etc.)
// which are always local.
func readGroupMembership(group, username string) (bool, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return false, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: groupname:x:gid:user1,user2,...
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		if parts[0] != group {
			continue
		}
		members := strings.Split(parts[3], ",")
		for _, m := range members {
			if strings.TrimSpace(m) == username {
				return true, nil
			}
		}
		return false, nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}
