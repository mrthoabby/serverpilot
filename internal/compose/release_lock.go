package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireProjectReleaseLock serializes the full release workflow for one
// project, including Docker, Nginx and registry changes.
func acquireProjectReleaseLock(project string) (func(), error) {
	if err := ValidateProjectName(project); err != nil {
		return nil, err
	}
	if err := ensureRegistryDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(registryDir, project+".release.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o660)
	if err != nil {
		return nil, fmt.Errorf("cannot acquire project release lock")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another release is already running for project %q", project)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
