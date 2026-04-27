package portalloc

import (
	"os"
	"syscall"
)

// lockFile acquires an exclusive advisory lock on the given path.
// It returns an unlock function that releases the lock and closes the file.
// This prevents race conditions when multiple `sp port` calls run concurrently.
//
// Hardening:
//   - O_NOFOLLOW prevents an attacker from pre-planting a symlink at the
//     lock path that would redirect the open into a sensitive location.
//     ServerPilot runs as root, so following a symlink to /etc/passwd would
//     let any local user crash, truncate, or otherwise corrupt arbitrary files.
//   - Mode 0600 prevents non-owner read/write of the lock file.
//   - The lock file lives inside a root-owned 0700 directory (see baseDir),
//     so non-root users cannot create or rename inside it.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}

	// LOCK_EX = exclusive, blocks until available.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
