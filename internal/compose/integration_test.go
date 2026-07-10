//go:build integration

package compose_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mrthoabby/serverpilot/internal/compose"
)

func TestIntegrationAnalyzeFixture(t *testing.T) {
	root := filepath.Join("testdata", "fixture")
	if _, err := os.Stat(root); err != nil {
		t.Skip("integration fixture not present")
	}
	compose.LockManagedAppsRootForTest(t, "testdata")

	res, err := AnalyzeProjectStrict("fixture", root, "docker-compose.yml")
	if err != nil {
		t.Fatalf("AnalyzeProjectStrict: %v", err)
	}
	if !res.CanDeploy {
		t.Fatalf("expected deployable fixture, blocking=%v", res.Blocking)
	}
}
