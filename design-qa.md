# Application Manager design QA

## Evidence

- Reference: `codex-clipboard-7eb963a9-7556-46d0-a80a-74286f4f9277.png`
- Comparison: `output/playwright/application-manager-reference-comparison.png`
- Desktop: `output/playwright/application-manager-project-1440.png`
- Tablet: `output/playwright/application-manager-project-1024.png`
- Mobile: `output/playwright/application-manager-project-390.png`
- Mobile navigation: `output/playwright/application-manager-sidebar-390.png`
- Module launcher: `output/playwright/application-manager-launcher-1440.png`

The supplied 4:3 reference and the rendered 4:3 project state were normalized
into one side-by-side comparison frame. Browser chrome outside the product was
not treated as part of the reference UI.

## Pass result

- P0: none.
- P1: none.
- P2: none blocking acceptance.

Verified:

- Application Manager is absent from the legacy horizontal tab row.
- The global module switcher opens as a pointer-dismissed listbox and provides
  explicit navigation between Server tools and Application Manager.
- There is no global Overview destination. A selected project is the default
  landing; Applications is the empty-project fallback.
- Sidebar hierarchy, inline searchable project/application submenus, active
  rows, line icons, status treatments, two-column cards, top search, and agent
  footer match the supplied visual direction.
- The 1440px, 1024px, and 390px layouts have no horizontal overflow. On mobile,
  the sidebar becomes an accessible drawer with a dismissible backdrop.
- The sole browser-console message in the static QA harness is its intentionally
  absent preview favicon; the module emitted no runtime error.

## Intentional differences

- The reference includes Worker and Mobile sample cards. The implementation
  exposes only Next.js Frontend and REST API, per the accepted product model.
- The ServerPilot module switcher is an integration control outside the module
  reference and was added to keep Application Manager independent from legacy
  dashboard tabs.
