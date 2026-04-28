// Package permissions implements granular per-user permission management for
// ServerPilot deploy users. It exposes three orthogonal grant primitives:
//
//   - Filesystem ACLs on managed application directories (/opt/<app>/) via
//     POSIX ACL (setfacl/getfacl). NEVER chmod and NEVER chown — those would
//     either expose the directory to every system user or destroy the
//     ServerPilot ownership tracking.
//
//   - Group membership for system applications that publish a unix group
//     (Docker → "docker"). Reversible via gpasswd. Group membership is
//     evaluated at login, so revoking does NOT terminate active sessions —
//     callers should surface that in the UI.
//
//   - Sudoers fragments scoped to a single hardcoded command per capability,
//     installed in /etc/sudoers.d/ with mode 0440 owned by root:root. Every
//     fragment is validated by `visudo -c -f` BEFORE the atomic rename, so
//     a malformed fragment can never lock the operator out.
//
// Source of truth: the live system. The audit log records every grant /
// revoke transition for forensics, but the UI reads getfacl / getent group /
// scan /etc/sudoers.d/ at request time. Drift is therefore visible, and
// manual fixes outside the dashboard are honored.
//
// The whole package re-validates every input at the SDK boundary even when
// the calling handler has already validated. This is deliberate: future
// code paths (other handlers, tests, scripts) MUST hit the same validation
// gate, and a single missed callsite would otherwise let an attacker pass a
// raw username with shell metacharacters into setfacl/gpasswd/visudo.
package permissions

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
)

// Level is the granted level on a managed-app directory. Closed enum.
type Level string

const (
	LevelNone  Level = "none"
	LevelRead  Level = "read"
	LevelWrite Level = "write"
)

func (l Level) Valid() bool {
	switch l {
	case LevelNone, LevelRead, LevelWrite:
		return true
	}
	return false
}

// Validation regexes mirror the rules used by internal/users and
// internal/apps. They are duplicated here so the package can be imported
// without pulling those packages and so a single audit can verify the gate.
var (
	usernameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	managedAppRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// Sentinel errors so callers (and tests) can branch on cause without
// matching string contents.
var (
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidManagedApp  = errors.New("invalid managed app name")
	ErrInvalidLevel       = errors.New("invalid permission level")
	ErrInvalidSystemApp   = errors.New("unknown system app")
	ErrInvalidCapability  = errors.New("unknown capability for this system app")
	ErrACLNotSupported    = errors.New("filesystem does not support POSIX ACLs")
	ErrConfirmTokenRequired = errors.New("confirmation token required for dangerous operation")
	ErrInvalidConfirmToken  = errors.New("invalid or expired confirmation token")
	ErrUserNotManaged       = errors.New("user is not a ServerPilot-managed deploy user")
	ErrAppNotManaged        = errors.New("application is not a ServerPilot-managed app")
)

// Service is the public façade. Callers (web handlers, CLI commands) should
// only ever interact with the package through this struct so we can mock it
// in tests and so all auditing flows through one path.
type Service struct {
	deps DependenciesProbe
	verifyUserManaged   func(username string) bool
	verifyAppManaged    func(app string) bool
}

// DependenciesProbe abstracts external command lookups so tests can inject
// fakes without needing setfacl / visudo on the test host.
type DependenciesProbe interface {
	HasACL(mountTarget string) bool // setfacl present AND filesystem mounted with acl
	HasVisudo() bool                // /usr/sbin/visudo
	HasGpasswd() bool               // /usr/bin/gpasswd
}

// NewService returns a Service wired against the live system. The two
// `verify*` callbacks are passed in so this package does not import
// internal/users or internal/apps (avoiding an import cycle).
func NewService(verifyUserManaged func(string) bool, verifyAppManaged func(string) bool) *Service {
	return &Service{
		deps:              defaultProbe{},
		verifyUserManaged: verifyUserManaged,
		verifyAppManaged:  verifyAppManaged,
	}
}

// validateBoundary runs every input through the gate before any system call.
// Used by every public method on Service so a single audit shows the path.
func (s *Service) validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return ErrInvalidUsername
	}
	if s.verifyUserManaged != nil && !s.verifyUserManaged(username) {
		return ErrUserNotManaged
	}
	return nil
}

func (s *Service) validateManagedApp(app string) error {
	if !managedAppRegex.MatchString(app) {
		return ErrInvalidManagedApp
	}
	if s.verifyAppManaged != nil && !s.verifyAppManaged(app) {
		return ErrAppNotManaged
	}
	return nil
}

// defaultProbe is the production wiring of DependenciesProbe.
type defaultProbe struct{}

func (defaultProbe) HasACL(mountTarget string) bool {
	if _, err := exec.LookPath("/usr/bin/setfacl"); err != nil {
		return false
	}
	// Try a getfacl on the target — if the kernel/fs combination does not
	// support ACLs, getfacl returns an error. We probe rather than parse
	// /proc/mounts because mount option discovery is brittle (bind mounts,
	// remounts, btrfs subvolumes). Probe is canonical.
	out, err := exec.Command("/usr/bin/getfacl", "--", mountTarget).CombinedOutput()
	if err != nil {
		return false
	}
	// A successful getfacl on a directory with ACLs always emits at least
	// one "user::" line.
	return len(out) > 0
}

func (defaultProbe) HasVisudo() bool {
	_, err := exec.LookPath("/usr/sbin/visudo")
	return err == nil
}

func (defaultProbe) HasGpasswd() bool {
	_, err := exec.LookPath("/usr/sbin/gpasswd")
	return err == nil
}

// SystemCapabilities reports which permission primitives are available on
// the host. Called at startup AND on every settings page render so the UI
// can disable controls with a clear reason instead of failing silently.
//
// The split between `ACLToolsMissing` and `ACLFsUnsupported` lets the UI
// offer one-click auto-install (apt install acl) only when the cause is
// the missing package — never when the filesystem itself doesn't support
// ACLs, since that would require a remount or fstab edit, both of which
// are too high-risk to one-click. Operator-action is preserved for those.
type SystemCapabilities struct {
	ACL              bool   `json:"acl"`
	ACLReason        string `json:"acl_reason,omitempty"`
	ACLToolsMissing  bool   `json:"acl_tools_missing,omitempty"`  // can be auto-fixed via apt install acl
	ACLFsUnsupported bool   `json:"acl_fs_unsupported,omitempty"` // requires manual remount / fstab edit
	ACLMountTarget   string `json:"acl_mount_target,omitempty"`   // e.g. "/" or "/opt", for the suggested remount command
	Sudoers          bool   `json:"sudoers"`
	Groups           bool   `json:"groups"`
}

// HasACLTools is split out so the UI can distinguish "package missing"
// (auto-fixable) from "filesystem doesn't support" (operator-action). The
// previous combined HasACL also still works and is what the grant /
// revoke paths consult; this one is purely advisory for the dashboard.
type extendedProbe interface {
	DependenciesProbe
	HasACLTools() bool
	FilesystemSupportsACL(path string) (bool, string) // (ok, mountTarget)
}

func (defaultProbe) HasACLTools() bool {
	if _, err := exec.LookPath("/usr/bin/setfacl"); err != nil {
		return false
	}
	if _, err := exec.LookPath("/usr/bin/getfacl"); err != nil {
		return false
	}
	return true
}

// FilesystemSupportsACL probes the filesystem holding `path` for ACL
// support. Returns (ok, mountTarget). The mountTarget is the directory
// the operator would need to remount if support is missing — useful for
// the UI suggestion. Probe is canonical (we run getfacl); we do not parse
// /proc/mounts because mount-option discovery is brittle (bind mounts,
// remounts, btrfs subvolumes).
func (defaultProbe) FilesystemSupportsACL(path string) (bool, string) {
	target := path
	out, err := exec.Command("/usr/bin/getfacl", "--", path).CombinedOutput()
	if err == nil && len(out) > 0 {
		return true, target
	}
	return false, target
}

func (s *Service) Capabilities() SystemCapabilities {
	caps := SystemCapabilities{
		Sudoers: s.deps.HasVisudo(),
		Groups:  s.deps.HasGpasswd(),
	}
	probe, isExtended := s.deps.(extendedProbe)
	if !isExtended {
		// Fall back to the simple combined check.
		caps.ACL = s.deps.HasACL("/opt")
		if !caps.ACL {
			caps.ACLReason = "POSIX ACLs unavailable on the filesystem holding /opt — install acl package and remount with the 'acl' option"
		}
		return caps
	}

	caps.ACLMountTarget = "/opt"
	hasTools := probe.HasACLTools()
	if !hasTools {
		caps.ACL = false
		caps.ACLToolsMissing = true
		caps.ACLReason = "The 'acl' package is not installed. Click 'Install ACL support' to install it via apt."
		return caps
	}
	fsOK, target := probe.FilesystemSupportsACL("/opt")
	caps.ACLMountTarget = target
	if !fsOK {
		caps.ACL = false
		caps.ACLFsUnsupported = true
		caps.ACLReason = "POSIX ACLs are not active on the filesystem holding /opt. The 'acl' package is installed but the filesystem needs to be remounted with the 'acl' option (or mounted on a filesystem that supports ACLs)."
		return caps
	}
	caps.ACL = true
	return caps
}

// FormatExecError converts an exec.ExitError into a generic, log-safe
// description. We deliberately do NOT propagate stderr to API callers —
// stderr from setfacl/gpasswd/visudo can leak file paths and account hints.
// Callers log the full error internally and return only the wrapped
// sentinel to the HTTP layer.
func FormatExecError(stage string, err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("%s failed with exit code %d", stage, exitErr.ExitCode())
	}
	return fmt.Errorf("%s failed", stage)
}
