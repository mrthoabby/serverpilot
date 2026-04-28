package permissions

import (
	"errors"
)

// SystemAppState is what the UI renders for an installed app's
// permissions tab. All values reflect LIVE system state (membership in
// /etc/group, presence of the sudoers fragment in /etc/sudoers.d/) — never
// the registry. This is per the design choice to surface drift.
type SystemAppState struct {
	App          string                  `json:"app"`
	Display      string                  `json:"display"`
	Users        []SystemAppUserState    `json:"users"`
	Capabilities []SystemAppCapability   `json:"capabilities"`
}

// SystemAppCapability is a flattened capability description (group OR
// sudoers rule) the UI renders one toggle for.
type SystemAppCapability struct {
	Slug        string `json:"slug"`
	Kind        string `json:"kind"` // "group" | "sudoers"
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
	Warning     string `json:"warning,omitempty"`
	Detail      string `json:"detail,omitempty"` // group name for group caps, command for sudoers
}

// SystemAppUserState reports per-user toggle states for one app.
type SystemAppUserState struct {
	Username     string          `json:"username"`
	Capabilities map[string]bool `json:"capabilities"` // slug → granted?
}

// GetSystemAppState assembles the LIVE state for `app`. It iterates over
// the static template, every managed deploy user, and reports membership
// + sudoers fragment presence.
//
// `listManagedUsers` is injected so this package does not import
// internal/users (avoids an import cycle).
func (s *Service) GetSystemAppState(app string, listManagedUsers func() []string) (*SystemAppState, error) {
	tmpl, ok := systemAppTemplates[app]
	if !ok {
		return nil, ErrInvalidSystemApp
	}

	state := &SystemAppState{App: app, Display: tmpl.Display}

	for _, g := range tmpl.Groups {
		state.Capabilities = append(state.Capabilities, SystemAppCapability{
			Slug:        g.Slug,
			Kind:        "group",
			Description: g.Description,
			Dangerous:   g.Dangerous,
			Warning:     g.Warning,
			Detail:      g.Group,
		})
	}
	for _, r := range tmpl.Sudoers {
		state.Capabilities = append(state.Capabilities, SystemAppCapability{
			Slug:        r.Slug,
			Kind:        "sudoers",
			Description: r.Description,
			Dangerous:   r.Dangerous,
			Detail:      r.Command,
		})
	}

	for _, username := range listManagedUsers() {
		// Defence in depth: skip any name that doesn't match the regex
		// even though the source is trusted.
		if !usernameRegex.MatchString(username) {
			continue
		}
		userState := SystemAppUserState{
			Username:     username,
			Capabilities: map[string]bool{},
		}
		for _, g := range tmpl.Groups {
			member, _ := readGroupMembership(g.Group, username)
			userState.Capabilities[g.Slug] = member
		}
		for _, r := range tmpl.Sudoers {
			has, _ := s.HasSudoersGrant(username, r.Slug)
			userState.Capabilities[r.Slug] = has
		}
		state.Users = append(state.Users, userState)
	}
	return state, nil
}

// GrantSystemCapability is the single entry point used by the web layer
// when an admin toggles a capability ON. It dispatches to GrantGroup or
// GrantSudoers based on the slug. The web handler is responsible for
// having validated the confirm token first.
func (s *Service) GrantSystemCapability(actor, app, slug, username string) error {
	if _, ok := systemAppTemplates[app]; !ok {
		return ErrInvalidSystemApp
	}
	if g, gApp, ok := LookupGroupCapability(slug); ok {
		if gApp != app {
			return errors.New("capability does not belong to this app")
		}
		return s.GrantGroup(actor, username, g.Group)
	}
	if r, ok := lookupSudoersRule(slug); ok {
		if r.App != app {
			return errors.New("capability does not belong to this app")
		}
		return s.GrantSudoers(actor, username, slug)
	}
	return ErrInvalidCapability
}

// RevokeSystemCapability is the inverse of GrantSystemCapability.
func (s *Service) RevokeSystemCapability(actor, app, slug, username string) error {
	if _, ok := systemAppTemplates[app]; !ok {
		return ErrInvalidSystemApp
	}
	if g, gApp, ok := LookupGroupCapability(slug); ok {
		if gApp != app {
			return errors.New("capability does not belong to this app")
		}
		return s.RevokeGroup(actor, username, g.Group)
	}
	if r, ok := lookupSudoersRule(slug); ok {
		if r.App != app {
			return errors.New("capability does not belong to this app")
		}
		return s.RevokeSudoers(actor, username, slug)
	}
	return ErrInvalidCapability
}

// IsCapabilityDangerous returns true if a confirm token is required for
// this capability slug. The web handler uses this to decide whether to
// require the token.
func IsCapabilityDangerous(slug string) bool {
	if g, _, ok := LookupGroupCapability(slug); ok {
		return g.Dangerous
	}
	if r, ok := lookupSudoersRule(slug); ok {
		return r.Dangerous
	}
	return false
}

// FSStateForApp returns the LIVE per-user ACL state on /opt/<app>,
// projected over the provided list of managed deploy users. Users that
// are not deploy users are stripped from the result so the UI is
// consistent with what the dashboard manages.
func (s *Service) FSStateForApp(app string, listManagedUsers func() []string) (map[string]Level, error) {
	live, err := s.ListFSGrants(app)
	if err != nil {
		return nil, err
	}
	managedSet := map[string]bool{}
	for _, u := range listManagedUsers() {
		if usernameRegex.MatchString(u) {
			managedSet[u] = true
		}
	}
	result := map[string]Level{}
	for u := range managedSet {
		result[u] = LevelNone
	}
	for _, g := range live {
		if managedSet[g.Username] {
			result[g.Username] = g.Level
		}
	}
	return result, nil
}

// FSCapabilityIsDangerous applies to FS grants. We currently treat
// `write` as non-dangerous (it's the normal deploy path) and `read` as
// non-dangerous. Reserved for future levels.
func FSCapabilityIsDangerous(level Level) bool {
	return false
}
