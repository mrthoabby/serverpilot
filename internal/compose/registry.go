package compose

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	registryMu  sync.Mutex
	registryDir = RegistryRoot
)

type projectRegistry struct {
	Projects []ProjectRecord `json:"projects"`
}

func registryPath() string { return filepath.Join(registryDir, "projects.json") }
func registryLockPath() string {
	return filepath.Join(registryDir, "projects.json.lock")
}

func ensureRegistryDir() error {
	if err := os.MkdirAll(registryDir, 0o2770); err != nil {
		return fmt.Errorf("cannot create compose registry")
	}
	return nil
}

func withRegistry(fn func(*projectRegistry) error) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	if err := ensureRegistryDir(); err != nil {
		return err
	}
	unlock, err := acquireRegistryLock()
	if err != nil {
		return err
	}
	defer unlock()
	reg := loadRegistry()
	if err := fn(reg); err != nil {
		return err
	}
	return saveRegistry(reg)
}

func loadRegistry() *projectRegistry {
	f, err := os.OpenFile(registryPath(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return &projectRegistry{}
	}
	defer f.Close()
	var reg projectRegistry
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return &projectRegistry{}
	}
	return &reg
}

func saveRegistry(reg *projectRegistry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(registryDir, ".compose-projects-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o660); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, registryPath())
}

func acquireRegistryLock() (func(), error) {
	f, err := os.OpenFile(registryLockPath(), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o660)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// NewGenerationID returns a random generation identifier.
func NewGenerationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ListProjects returns all registered compose projects.
func ListProjects() ([]ProjectRecord, error) {
	var out []ProjectRecord
	err := withRegistry(func(reg *projectRegistry) error {
		out = append(out, reg.Projects...)
		return nil
	})
	return out, err
}

// GetProject returns a project by name.
func GetProject(name string) (ProjectRecord, bool, error) {
	var found ProjectRecord
	ok := false
	err := withRegistry(func(reg *projectRegistry) error {
		for _, p := range reg.Projects {
			if p.Name == name {
				found = p
				ok = true
				return nil
			}
		}
		return nil
	})
	return found, ok, err
}

// UpsertProject inserts or replaces a project record.
func UpsertProject(rec ProjectRecord) error {
	return withRegistry(func(reg *projectRegistry) error {
		now := time.Now().UTC()
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = now
		}
		rec.UpdatedAt = now
		for i, p := range reg.Projects {
			if p.Name == rec.Name {
				reg.Projects[i] = rec
				return nil
			}
		}
		reg.Projects = append(reg.Projects, rec)
		return nil
	})
}

// DeleteProject removes a project from the registry.
func DeleteProject(name string) error {
	return withRegistry(func(reg *projectRegistry) error {
		next := reg.Projects[:0]
		for _, p := range reg.Projects {
			if p.Name != name {
				next = append(next, p)
			}
		}
		reg.Projects = next
		return nil
	})
}

// ProjectArtifactsDir returns the generated artifacts directory for a project.
func ProjectArtifactsDir(projectName string) (string, error) {
	if err := ValidateProjectName(projectName); err != nil {
		return "", err
	}
	dir := filepath.Join(registryDir, projectName)
	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return "", err
	}
	return dir, nil
}

// GenerationDir returns the directory for one generation's generated files.
func GenerationDir(projectName, generationID string) (string, error) {
	base, err := ProjectArtifactsDir(projectName)
	if err != nil {
		return "", err
	}
	if generationID == "" {
		return "", fmt.Errorf("generation id is required")
	}
	dir := filepath.Join(base, generationID)
	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return "", err
	}
	return dir, nil
}

// SetRegistryRootForTests overrides the registry directory in tests.
func SetRegistryRootForTests(root string) func() {
	old := registryDir
	registryDir = root
	return func() { registryDir = old }
}
