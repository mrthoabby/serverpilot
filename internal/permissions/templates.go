package permissions

// Templates declare the permission surface ServerPilot is willing to
// manage on behalf of the admin. They are HARDCODED — the dashboard never
// lets an operator define new rules at runtime, because every entry here
// is effectively a privileged action and only a code review (not a UI
// click) should be able to add one.
//
// Two flavours:
//   - GroupCapability — flips a unix group membership via gpasswd.
//   - SudoersRule     — installs a fixed `Cmnd` line into /etc/sudoers.d/.
//
// Sudoers rules NEVER contain wildcards or shell metacharacters in their
// Command field. A wildcard like `/usr/bin/certbot *` lets the user pass
// arbitrary flags (`--post-hook 'rm -rf /'`); we therefore enumerate every
// useful invocation as its own slug.

// SystemAppDefinition is the public shape rendered to the UI for one app.
type SystemAppDefinition struct {
	App           string                `json:"app"`
	Display       string                `json:"display"`
	GroupCaps     []GroupCapabilityView `json:"group_capabilities,omitempty"`
	SudoersRules  []SudoersRuleView     `json:"sudoers_rules,omitempty"`
}

type GroupCapabilityView struct {
	Slug        string `json:"slug"` // stable identifier used by the API
	Group       string `json:"group"`
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
	Warning     string `json:"warning,omitempty"`
}

type SudoersRuleView struct {
	Slug        string `json:"slug"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Dangerous   bool   `json:"dangerous"`
}

// SudoersRule is the internal representation. Slug is the user-facing
// identifier and is also part of the on-disk filename in /etc/sudoers.d/,
// so it is constrained to sudoersRuleRegex (see sudoers.go).
type SudoersRule struct {
	Slug        string
	App         string
	Description string
	Command     string // absolute path + EXACT args, no wildcards
	Dangerous   bool
}

// systemAppTemplates is the closed catalogue. Adding an entry requires a
// code change AND review.
var systemAppTemplates = map[string]systemAppTemplate{
	"docker": {
		Display: "Docker",
		Groups: []groupCap{
			{
				Slug:        "docker-noroot",
				Group:       "docker",
				Description: "Run docker commands without sudo",
				Dangerous:   true,
				Warning:     "Members of the docker group can mount / inside a container and become root. Treat as a root grant.",
			},
		},
	},
	"nginx": {
		Display: "Nginx",
		Sudoers: []SudoersRule{
			{
				Slug:        "nginx-reload",
				App:         "nginx",
				Description: "Reload nginx configuration without password",
				Command:     "/usr/bin/systemctl reload nginx",
				Dangerous:   false,
			},
			{
				Slug:        "nginx-test",
				App:         "nginx",
				Description: "Validate nginx configuration (nginx -t) without password",
				Command:     "/usr/sbin/nginx -t",
				Dangerous:   false,
			},
		},
	},
}

type systemAppTemplate struct {
	Display string
	Groups  []groupCap
	Sudoers []SudoersRule
}

type groupCap struct {
	Slug        string
	Group       string
	Description string
	Dangerous   bool
	Warning     string
}

// SystemAppDefinitions returns every system app the dashboard knows how to
// manage. Stable order — sorted by app key — so the UI is deterministic.
func SystemAppDefinitions() []SystemAppDefinition {
	keys := make([]string, 0, len(systemAppTemplates))
	for k := range systemAppTemplates {
		keys = append(keys, k)
	}
	// inline insertion sort — small N, avoid pulling sort just for this.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}

	out := make([]SystemAppDefinition, 0, len(keys))
	for _, k := range keys {
		t := systemAppTemplates[k]
		def := SystemAppDefinition{App: k, Display: t.Display}
		for _, g := range t.Groups {
			def.GroupCaps = append(def.GroupCaps, GroupCapabilityView{
				Slug: g.Slug, Group: g.Group, Description: g.Description,
				Dangerous: g.Dangerous, Warning: g.Warning,
			})
		}
		for _, r := range t.Sudoers {
			def.SudoersRules = append(def.SudoersRules, SudoersRuleView{
				Slug: r.Slug, Description: r.Description,
				Command: r.Command, Dangerous: r.Dangerous,
			})
		}
		out = append(out, def)
	}
	return out
}

// LookupGroupCapability finds a group capability by its slug across all
// system apps. Returns (cap, app, ok). Used by the grant handler so the
// caller doesn't have to know which app the slug belongs to — it's
// uniquely identified by its slug.
func LookupGroupCapability(slug string) (groupCap, string, bool) {
	for app, t := range systemAppTemplates {
		for _, g := range t.Groups {
			if g.Slug == slug {
				return g, app, true
			}
		}
	}
	return groupCap{}, "", false
}

// lookupSudoersRule is exported within the package so sudoers.go can
// resolve a rule slug back to its hardcoded command. Returns (rule, ok).
func lookupSudoersRule(slug string) (SudoersRule, bool) {
	for _, t := range systemAppTemplates {
		for _, r := range t.Sudoers {
			if r.Slug == slug {
				return r, true
			}
		}
	}
	return SudoersRule{}, false
}
