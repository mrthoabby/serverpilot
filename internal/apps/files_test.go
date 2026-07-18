package apps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAppRelPath(t *testing.T) {
	tests := []struct {
		in    string
		want  string
		isErr bool
	}{
		{"", "", false},
		{".", "", false},
		{"logs", "logs", false},
		{"data/cache", "data/cache", false},
		{"../etc", "", true},
		{"logs/../secret", "", true},
		{"/logs/", "logs", false},
	}
	for _, tc := range tests {
		got, err := normalizeAppRelPath(tc.in)
		if tc.isErr {
			if err == nil {
				t.Fatalf("normalizeAppRelPath(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeAppRelPath(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeAppRelPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPathContainedIn(t *testing.T) {
	base := "/opt/myapp"
	if !pathContainedIn(base, "/opt/myapp") {
		t.Fatal("expected app root to be contained")
	}
	if !pathContainedIn(base, "/opt/myapp/logs") {
		t.Fatal("expected child dir to be contained")
	}
	if pathContainedIn(base, "/opt/other") {
		t.Fatal("expected sibling app to be rejected")
	}
	if pathContainedIn(base, "/etc/passwd") {
		t.Fatal("expected outside path to be rejected")
	}
}

func TestResolveContainedAppPath(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "shop")
	if err := os.MkdirAll(filepath.Join(appDir, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	absApp, err := filepath.Abs(appDir)
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolveContainedAppPath(absApp, "logs")
	if err != nil {
		t.Fatalf("resolveContainedAppPath logs: %v", err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(absApp, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolveContainedAppPath logs = %q, want %q", got, want)
	}

	if _, err := resolveContainedAppPath(absApp, ".."); err == nil {
		t.Fatal("expected parent traversal to fail")
	}
}
