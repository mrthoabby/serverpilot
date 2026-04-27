package portalloc

import (
	"os"
	"syscall"
)

// lockFile acquires an exclusive advisory lock on the given path.
// It returns an unlock function that releases the lock and closes the file.
// This prevents race conditions when multiple `sp port` calls run concurrently.
func lockFile(path string) (unlock func(), err error) {
	// 0666 so any user (root, deploy users, etc.) can acquire the lock.
	// The file lives in /tmp and is ephemeral — broad permissions are safe here.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	// LOCK_EX = exclusive, blocks until available.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}

	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
