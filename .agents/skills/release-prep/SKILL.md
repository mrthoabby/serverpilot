---
name: release-prep
description: Prepares a new sp release — bumps version.go, validates the build, runs tests, and summarizes changes since the last tag. Invoke with /release-prep.
disable-model-invocation: true
---

Steps:
1. Read current version from version.go
2. Ask user for the new version string (format: vX.Y.Z)
3. Update version.go with the new string
4. Run: go build -o sp . — confirm it succeeds
5. Run tests and vet with writable cache:
   mkdir -p /private/tmp/serverpilot-go-cache /private/tmp/serverpilot-go-modcache
   env GOCACHE=/private/tmp/serverpilot-go-cache GOMODCACHE=/private/tmp/serverpilot-go-modcache go test ./...
   env GOCACHE=/private/tmp/serverpilot-go-cache GOMODCACHE=/private/tmp/serverpilot-go-modcache go vet ./...
6. Output git log summary since last tag: git log $(git describe --tags --abbrev=0)..HEAD --oneline
7. Print next manual steps: git tag vX.Y.Z, git push --tags, run vs-pre-run/Makefile targets
