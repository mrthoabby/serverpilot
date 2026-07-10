package sites

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/nginx"
)

// ActivateRedirect overlays a temporary redirect on an existing site config.
func ActivateRedirect(configName string, spec RedirectSpec) error {
	if spec.Code == 0 {
		spec.Code = 301
	}
	if spec.Code != 301 && spec.Code != 302 {
		return fmt.Errorf("invalid redirect code")
	}
	if strings.TrimSpace(spec.Target) == "" {
		return fmt.Errorf("redirect target required")
	}

	rec, ok, err := GetByConfigName(configName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("site not found in registry")
	}
	if rec.State == StateRedirectOverlay {
		return fmt.Errorf("redirect already active")
	}

	original, err := nginx.ReadConfigContent(configName)
	if err != nil {
		return fmt.Errorf("failed to read site config")
	}
	hash := sha256.Sum256([]byte(original))
	backupPath := filepath.Join(backupsPath(), configName+".redirect."+rec.ID)
	if err := writeBackupAtomic(backupPath, []byte(original)); err != nil {
		return fmt.Errorf("failed to store backup")
	}

	overlay, err := buildRedirectOverlay(original, spec)
	if err != nil {
		return fmt.Errorf("failed to build redirect overlay")
	}
	if _, err := nginx.WriteConfigContent(configName, overlay, true); err != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("nginx rejected redirect overlay")
	}
	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("nginx reload failed")
	}

	rec.State = StateRedirectOverlay
	rec.Redirect = &spec
	rec.Backup = &RedirectBackup{
		ConfigName:   configName,
		OriginalHash: hex.EncodeToString(hash[:]),
		BackupPath:   backupPath,
		ActivatedAt:  time.Now().UTC(),
	}
	return Upsert(rec)
}

// DeactivateRedirect restores the original config or removes managed overlay markers.
func DeactivateRedirect(configName string, forceOriginal bool) error {
	rec, ok, err := GetByConfigName(configName)
	if err != nil {
		return err
	}
	if !ok || rec.State != StateRedirectOverlay || rec.Backup == nil {
		return fmt.Errorf("no active redirect for site")
	}

	current, err := nginx.ReadConfigContent(configName)
	if err != nil {
		return fmt.Errorf("failed to read current config")
	}
	backupData, err := os.ReadFile(rec.Backup.BackupPath)
	if err != nil {
		return fmt.Errorf("backup not found")
	}
	currentHash := sha256.Sum256([]byte(current))
	backupHash := sha256.Sum256(backupData)

	if forceOriginal || hex.EncodeToString(currentHash[:]) == hex.EncodeToString(backupHash[:]) {
		if _, err := nginx.WriteConfigContent(configName, string(backupData), true); err != nil {
			return fmt.Errorf("nginx rejected restored config")
		}
	} else if strings.Contains(current, "# serverpilot_redirect_overlay") {
		restored, err := stripRedirectOverlay(current, string(backupData))
		if err != nil {
			return fmt.Errorf("redirect overlay conflict: config changed while redirect was active")
		}
		if _, err := nginx.WriteConfigContent(configName, restored, true); err != nil {
			return fmt.Errorf("nginx rejected restored config")
		}
	} else {
		return fmt.Errorf("redirect overlay conflict: config changed while redirect was active")
	}

	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("nginx reload failed")
	}
	_ = os.Remove(rec.Backup.BackupPath)
	rec.State = StateActive
	rec.Redirect = nil
	rec.Backup = nil
	return Upsert(rec)
}

func buildRedirectOverlay(original string, spec RedirectSpec) (string, error) {
	var b strings.Builder
	b.WriteString("# serverpilot_redirect_overlay begin\n")
	for _, line := range strings.Split(original, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "location ") {
			b.WriteString(line + "\n")
			b.WriteString(fmt.Sprintf("        return %d %s$request_uri;\n", spec.Code, spec.Target))
			b.WriteString("    }\n")
			continue
		}
		if strings.HasPrefix(trim, "proxy_pass ") {
			continue
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("# serverpilot_redirect_overlay end\n")
	return b.String(), nil
}

func stripRedirectOverlay(current, backup string) (string, error) {
	if !strings.Contains(current, "# serverpilot_redirect_overlay begin") {
		return "", fmt.Errorf("overlay markers missing")
	}
	return backup, nil
}

func writeBackupAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".backup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
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
	return os.Rename(tmpPath, path)
}
