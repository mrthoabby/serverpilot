package permissions

import (
	"os"
	"sync"
)

// Resolved absolute paths to the binaries this package invokes. We never
// fall back to $PATH lookup — every candidate is an absolute path under
// /usr/{,s}bin, /bin, or /sbin, which are root-owned on every supported
// distro. Probing absolute candidates instead of hardcoding one path
// makes the package portable across Debian/Ubuntu (gpasswd in /usr/bin),
// older RHEL-style systems (gpasswd in /usr/sbin), and merged-/usr
// systems where both work via symlink.
//
// Each entry is resolved at most once; the result is cached for the
// process lifetime since binary install paths don't change at runtime.

var (
	binCacheMu sync.Mutex
	binCache   = map[string]string{}
)

// findBinary returns the first existing absolute path among `candidates`,
// or "" if none exist. Uses os.Stat (not exec.LookPath) because LookPath
// follows symlinks and doesn't enforce executable bit; we want a strict
// "is the file there and executable" check.
func findBinary(name string, candidates ...string) string {
	binCacheMu.Lock()
	defer binCacheMu.Unlock()
	if cached, ok := binCache[name]; ok {
		return cached
	}
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			binCache[name] = p
			return p
		}
	}
	binCache[name] = ""
	return ""
}

// Canonical path lookups. Order is "most common in modern Debian/Ubuntu"
// first, then older / RHEL-style locations. Because all candidates are
// absolute, none of them go through $PATH — adding a candidate is purely
// additive defence-in-depth, never an attack surface.

func gpasswdPath() string {
	return findBinary("gpasswd", "/usr/bin/gpasswd", "/usr/sbin/gpasswd", "/sbin/gpasswd", "/bin/gpasswd")
}

func visudoPath() string {
	return findBinary("visudo", "/usr/sbin/visudo", "/usr/bin/visudo", "/sbin/visudo")
}

func setfaclPath() string {
	return findBinary("setfacl", "/usr/bin/setfacl", "/bin/setfacl", "/usr/sbin/setfacl")
}

func getfaclPath() string {
	return findBinary("getfacl", "/usr/bin/getfacl", "/bin/getfacl", "/usr/sbin/getfacl")
}

// resetBinCache is exported only for tests that swap fakes into PATH.
// Production code never calls it.
func resetBinCache() {
	binCacheMu.Lock()
	defer binCacheMu.Unlock()
	binCache = map[string]string{}
}
