# Release Artifact Notes

## Scope

`release/**` contains committed platform binaries for historical ServerPilot versions.

## Rules

- Do not open, cat, or search inside these binaries.
- Use metadata commands only: `ls -lh`, `file`, `shasum -a 256`, or `sha256sum`.
- Modify this directory only for explicit release/version work.
- A release change should coordinate `version.go`, `release/<version>/sp-<os>-<arch>`, `homebrew/Formula/sp.rb`, installer/update download assumptions, and any checksum sidecars.

