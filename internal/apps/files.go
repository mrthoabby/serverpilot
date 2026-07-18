package apps

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxDirEntries = 500

// AppDirEntry describes one item inside a managed app directory listing.
type AppDirEntry struct {
	Name          string `json:"name"`
	Type          string `json:"type"` // dir, file, symlink, other
	Navigable     bool   `json:"navigable,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	Modified      string `json:"modified,omitempty"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
}

// AppDirListing is the response for browsing a managed app directory.
type AppDirListing struct {
	App        string        `json:"app"`
	Path       string        `json:"path"`
	ParentPath string        `json:"parent_path,omitempty"`
	Entries    []AppDirEntry `json:"entries"`
}

// ListAppDirectory returns a non-recursive listing of one directory inside
// /opt/<app>. relPath is relative to the app root (empty string = root).
func ListAppDirectory(appName, relPath string) (*AppDirListing, error) {
	if !validAppName.MatchString(appName) {
		return nil, fmt.Errorf("invalid app name")
	}

	mu.Lock()
	defer mu.Unlock()

	if !isManaged(appName) {
		return nil, fmt.Errorf("app is not managed")
	}

	normPath, err := normalizeAppRelPath(relPath)
	if err != nil {
		return nil, err
	}

	absApp, err := managedAppAbsDir(appName)
	if err != nil {
		return nil, err
	}

	absDir, err := resolveContainedAppPath(absApp, normPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Lstat(absDir)
	if err != nil {
		return nil, fmt.Errorf("path not found")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to list symlink path")
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory")
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory")
	}

	out := make([]AppDirEntry, 0, len(entries))
	for _, entry := range entries {
		if len(out) >= maxDirEntries {
			break
		}
		item, err := entryInfo(absApp, absDir, entry)
		if err != nil {
			continue
		}
		out = append(out, item)
	}

	sort.Slice(out, func(i, j int) bool {
		order := func(t string) int {
			switch t {
			case "dir":
				return 0
			case "symlink":
				return 1
			default:
				return 2
			}
		}
		oi, oj := order(out[i].Type), order(out[j].Type)
		if oi != oj {
			return oi < oj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})

	parent := ""
	if normPath != "" {
		parent = filepath.Dir(normPath)
		if parent == "." {
			parent = ""
		}
	}

	return &AppDirListing{
		App:        appName,
		Path:       normPath,
		ParentPath: parent,
		Entries:    out,
	}, nil
}

func normalizeAppRelPath(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.Trim(rel, "/")
	if rel == "" || rel == "." {
		return "", nil
	}
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("invalid path")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid path")
		}
	}
	return rel, nil
}

func managedAppAbsDir(appName string) (string, error) {
	appDir := filepath.Join(appsBaseDir, appName)
	absApp, err := filepath.Abs(appDir)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	rel, err := filepath.Rel(appsBaseDir, absApp)
	if err != nil || strings.HasPrefix(rel, "..") || strings.ContainsRune(rel, filepath.Separator) {
		return "", fmt.Errorf("path outside apps base")
	}

	info, err := os.Lstat(absApp)
	if err != nil {
		return "", fmt.Errorf("app directory not found")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing symlinked app directory")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("app path is not a directory")
	}
	return absApp, nil
}

func resolveContainedAppPath(absApp, relPath string) (string, error) {
	target := absApp
	if relPath != "" {
		target = filepath.Join(absApp, relPath)
	}

	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("path not found")
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	appReal, err := filepath.EvalSymlinks(absApp)
	if err != nil {
		return "", fmt.Errorf("invalid app path")
	}
	appReal, err = filepath.Abs(appReal)
	if err != nil {
		return "", fmt.Errorf("invalid app path")
	}
	if !pathContainedIn(appReal, real) {
		return "", fmt.Errorf("path outside app directory")
	}
	return real, nil
}

func pathContainedIn(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, "..")
}

func entryInfo(absApp, absDir string, entry os.DirEntry) (AppDirEntry, error) {
	fullPath := filepath.Join(absDir, entry.Name())
	info, err := os.Lstat(fullPath)
	if err != nil {
		return AppDirEntry{}, err
	}

	item := AppDirEntry{
		Name:      entry.Name(),
		SizeBytes: info.Size(),
		Modified:  info.ModTime().UTC().Format(time.RFC3339),
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		item.Type = "symlink"
		target, err := os.Readlink(fullPath)
		if err == nil && target != "" {
			item.SymlinkTarget = filepath.Base(target)
		}
		if real, err := filepath.EvalSymlinks(fullPath); err == nil {
			if pathContainedIn(absApp, real) {
				if realInfo, err := os.Stat(real); err == nil && realInfo.IsDir() {
					item.Navigable = true
				}
			} else {
				item.SymlinkTarget = "(outside app)"
			}
		}
	case info.IsDir():
		item.Type = "dir"
		item.Navigable = true
	case info.Mode().IsRegular():
		item.Type = "file"
	default:
		item.Type = "other"
	}

	return item, nil
}
