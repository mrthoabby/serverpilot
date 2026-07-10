package sites

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mrthoabby/serverpilot/internal/templates"
)

const (
	registryName = "sites.json"
	lockName     = "sites.json.lock"
	backupDir    = "site-backups"
)

var registryRoot = "/var/lib/serverpilot"

var registryMu sync.Mutex

// SiteState describes lifecycle state for a managed site.
type SiteState string

const (
	StateActive          SiteState = "active"
	StateDisabled        SiteState = "disabled"
	StateRedirectOverlay SiteState = "redirect_overlay"
)

// RedirectSpec holds temporary redirect settings on an existing site.
type RedirectSpec struct {
	Target       string `json:"target"`
	Code         int    `json:"code"`
	DelaySeconds int    `json:"delay_seconds,omitempty"`
	Message      string `json:"message,omitempty"`
}

// RedirectBackup tracks stored original config for restore.
type RedirectBackup struct {
	ConfigName   string    `json:"config_name"`
	OriginalHash string    `json:"original_hash"`
	BackupPath   string    `json:"backup_path"`
	ActivatedAt  time.Time `json:"activated_at"`
}

// SiteRecord is the authoritative ownership record for a managed site.
type SiteRecord struct {
	ID            string                    `json:"id"`
	ContainerID   string                    `json:"container_id"`
	ContainerName string                    `json:"container_name"`
	HostPort      int                       `json:"host_port"`
	ContainerPort int                       `json:"container_port,omitempty"`
	Domain        string                    `json:"domain"`
	ConfigName    string                    `json:"config_name"`
	Template      templates.TemplateType    `json:"template"`
	Options       templates.TemplateOptions `json:"options"`
	State         SiteState                 `json:"state"`
	Redirect      *RedirectSpec             `json:"redirect,omitempty"`
	Backup        *RedirectBackup           `json:"backup,omitempty"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
}

type registry struct {
	Sites []SiteRecord `json:"sites"`
}

func registryPath() string { return filepath.Join(registryRoot, registryName) }
func lockPath() string     { return filepath.Join(registryRoot, lockName) }
func backupsPath() string  { return filepath.Join(registryRoot, backupDir) }

// NewSiteID returns a random hex site identifier.
func NewSiteID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func withRegistryLock(fn func(*registry) error) error {
	registryMu.Lock()
	defer registryMu.Unlock()

	if err := ensureBaseDir(); err != nil {
		return err
	}
	unlock, err := acquireLock()
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

func loadRegistry() *registry {
	f, err := os.OpenFile(registryPath(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return &registry{}
	}
	defer f.Close()
	var reg registry
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return &registry{}
	}
	return &reg
}

func saveRegistry(reg *registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(registryRoot, ".sites-*.json")
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

func ensureBaseDir() error {
	if err := os.MkdirAll(registryRoot, 0o2770); err != nil {
		return fmt.Errorf("cannot create registry directory")
	}
	if err := os.MkdirAll(backupsPath(), 0o2770); err != nil {
		return fmt.Errorf("cannot create backup directory")
	}
	return nil
}

func acquireLock() (func(), error) {
	f, err := os.OpenFile(lockPath(), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o660)
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

// List returns all site records.
func List() ([]SiteRecord, error) {
	var out []SiteRecord
	err := withRegistryLock(func(reg *registry) error {
		out = append(out, reg.Sites...)
		return nil
	})
	return out, err
}

// GetByID returns a site record by ID.
func GetByID(id string) (SiteRecord, bool, error) {
	var found SiteRecord
	ok := false
	err := withRegistryLock(func(reg *registry) error {
		for _, s := range reg.Sites {
			if s.ID == id {
				found = s
				ok = true
				return nil
			}
		}
		return nil
	})
	return found, ok, err
}

// GetByConfigName returns a site record by nginx config filename.
func GetByConfigName(name string) (SiteRecord, bool, error) {
	var found SiteRecord
	ok := false
	err := withRegistryLock(func(reg *registry) error {
		for _, s := range reg.Sites {
			if s.ConfigName == name || s.Domain == name {
				found = s
				ok = true
				return nil
			}
		}
		return nil
	})
	return found, ok, err
}

// Upsert inserts or replaces a site record.
func Upsert(rec SiteRecord) error {
	return withRegistryLock(func(reg *registry) error {
		now := time.Now().UTC()
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = now
		}
		rec.UpdatedAt = now
		for i, s := range reg.Sites {
			if s.ID == rec.ID {
				reg.Sites[i] = rec
				return nil
			}
		}
		reg.Sites = append(reg.Sites, rec)
		return nil
	})
}

// Delete removes a site record by ID.
func Delete(id string) error {
	return withRegistryLock(func(reg *registry) error {
		out := reg.Sites[:0]
		for _, s := range reg.Sites {
			if s.ID != id {
				out = append(out, s)
			}
		}
		reg.Sites = out
		return nil
	})
}

// DeleteByConfigName removes a site record by nginx config filename or domain.
func DeleteByConfigName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	return withRegistryLock(func(reg *registry) error {
		out := reg.Sites[:0]
		for _, s := range reg.Sites {
			if s.ConfigName == name || strings.EqualFold(s.Domain, name) {
				continue
			}
			out = append(out, s)
		}
		reg.Sites = out
		return nil
	})
}

// SitesForContainer returns all records bound to a container name or ID.
func SitesForContainer(containerID, containerName string) ([]SiteRecord, error) {
	var out []SiteRecord
	err := withRegistryLock(func(reg *registry) error {
		for _, s := range reg.Sites {
			if s.ContainerID == containerID || (containerName != "" && s.ContainerName == containerName) {
				out = append(out, s)
			}
		}
		return nil
	})
	return out, err
}

// SitesOnHostPort returns records using the given host port.
func SitesOnHostPort(hostPort int) ([]SiteRecord, error) {
	var out []SiteRecord
	err := withRegistryLock(func(reg *registry) error {
		for _, s := range reg.Sites {
			if s.HostPort == hostPort {
				out = append(out, s)
			}
		}
		return nil
	})
	return out, err
}
