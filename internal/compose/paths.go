package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ManagedAppsRoot is the only allowed parent for compose projects.
var ManagedAppsRoot = "/opt"

// RegistryRoot stores compose registries and generated artifacts.
const RegistryRoot = "/var/lib/serverpilot/compose"

var (
	projectNameRegex  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	serviceNameRegex  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	managedRootTestMu sync.Mutex
)

func managedAppsRoot() string {
	return ManagedAppsRoot
}

// LockManagedAppsRootForTest serializes tests that override ManagedAppsRoot.
func LockManagedAppsRootForTest(t testingT, root string) {
	managedRootTestMu.Lock()
	old := ManagedAppsRoot
	ManagedAppsRoot = root
	t.Cleanup(func() {
		ManagedAppsRoot = old
		managedRootTestMu.Unlock()
	})
}

type testingT interface {
	Cleanup(func())
}

// ValidateProjectName ensures a stable compose project identifier.
func ValidateProjectName(name string) error {
	name = strings.TrimSpace(name)
	if !projectNameRegex.MatchString(name) {
		return fmt.Errorf("invalid project name")
	}
	return nil
}

// ValidateServiceName ensures a compose service name is safe for argv/env use.
func ValidateServiceName(name string) error {
	if !serviceNameRegex.MatchString(name) {
		return fmt.Errorf("invalid service name")
	}
	return nil
}

// ResolveProjectRoot canonicalizes and confines a project directory under /opt.
func ResolveProjectRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("project root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("invalid project root")
	}
	abs = filepath.Clean(abs)
	if err := assertUnderManagedRoot(abs); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("project root not found")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project root is not a directory")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("project root cannot be a symlink")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("project root resolution failed")
	}
	if err := assertUnderManagedRoot(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// ResolveComposeFile confines a compose file under the project root.
func ResolveComposeFile(projectRoot, composeFile string) (string, error) {
	projectRoot, err := ResolveProjectRoot(projectRoot)
	if err != nil {
		return "", err
	}
	composeFile = strings.TrimSpace(composeFile)
	if composeFile == "" {
		composeFile = "docker-compose.yml"
	}
	var abs string
	if filepath.IsAbs(composeFile) {
		abs = filepath.Clean(composeFile)
	} else {
		abs = filepath.Clean(filepath.Join(projectRoot, composeFile))
	}
	if err := assertContained(projectRoot, abs); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("compose file not found")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("compose file cannot be a symlink")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("compose file resolution failed")
	}
	if err := assertContained(projectRoot, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// ResolveContainedPath resolves relPath under projectRoot with symlink checks.
func ResolveContainedPath(projectRoot, relPath string) (string, error) {
	projectRoot, err := ResolveProjectRoot(projectRoot)
	if err != nil {
		return "", err
	}
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return "", fmt.Errorf("path is required")
	}
	var abs string
	if filepath.IsAbs(relPath) {
		abs = filepath.Clean(relPath)
	} else {
		abs = filepath.Clean(filepath.Join(projectRoot, relPath))
	}
	if err := assertContained(projectRoot, abs); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("path not found")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path cannot be a symlink")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("path resolution failed")
	}
	if err := assertContained(projectRoot, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func assertUnderManagedRoot(abs string) error {
	root := managedAppsRoot()
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("invalid managed root")
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootResolved = rootAbs
	}
	rootResolved = filepath.Clean(rootResolved)

	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return fmt.Errorf("project root resolution failed")
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return fmt.Errorf("project must live under %s", root)
	}
	return nil
}

func assertContained(projectRoot, target string) error {
	projectRoot = filepath.Clean(projectRoot)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(projectRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes project root")
	}
	return nil
}
