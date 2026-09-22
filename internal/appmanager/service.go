package appmanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultStateDir       = "/var/lib/serverpilot/appmanager"
	defaultDBPath         = defaultStateDir + "/appmanager.db"
	defaultKeyPath        = defaultStateDir + "/master.key"
	previewCleanupMarker  = ".cleanup-vnext-registry-username"
	previewCleanupMessage = "Application Manager preview state reset for the registry credential schema"
	maxPageSize           = 200
)

type Service struct {
	store *Store
	vault *vault
	now   func() time.Time
}

func OpenDefault() (*Service, error) {
	if err := cleanupPreproductionState(defaultStateDir); err != nil {
		return nil, err
	}
	return Open(defaultDBPath, defaultKeyPath)
}

// cleanupPreproductionState is a temporary, one-shot reset for the
// pre-production Application Manager schema. The marker prevents ordinary
// daemon restarts from deleting data created by this version. Remove this
// function and its OpenDefault call after the cleanup release has shipped.
func cleanupPreproductionState(stateDir string) error {
	if stateDir == "" || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) == "/" {
		return fmt.Errorf("invalid application manager cleanup directory")
	}
	parent := filepath.Dir(stateDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("prepare application manager cleanup parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("application manager cleanup parent is unsafe")
	}
	if info, err := os.Lstat(stateDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("application manager cleanup directory is unsafe")
		}
		marker := filepath.Join(stateDir, previewCleanupMarker)
		if markerInfo, markerErr := os.Lstat(marker); markerErr == nil {
			if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("application manager cleanup marker is unsafe")
			}
			return nil
		} else if !os.IsNotExist(markerErr) {
			return fmt.Errorf("inspect application manager cleanup marker: %w", markerErr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect application manager cleanup directory: %w", err)
	}
	if err := os.RemoveAll(stateDir); err != nil {
		return fmt.Errorf("reset pre-production application manager state: %w", err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		return fmt.Errorf("recreate application manager state directory: %w", err)
	}
	markerPath := filepath.Join(stateDir, previewCleanupMarker)
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create application manager cleanup marker: %w", err)
	}
	removeMarker := true
	defer func() {
		if removeMarker {
			_ = os.Remove(markerPath)
		}
	}()
	if _, err := marker.WriteString(previewCleanupMessage + "\n"); err != nil {
		_ = marker.Close()
		return fmt.Errorf("write application manager cleanup marker: %w", err)
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		return fmt.Errorf("sync application manager cleanup marker: %w", err)
	}
	if err := marker.Close(); err != nil {
		return fmt.Errorf("close application manager cleanup marker: %w", err)
	}
	removeMarker = false
	log.Printf("application manager: cleared pre-production state for the current schema")
	return nil
}

func Open(dbPath, keyPath string) (*Service, error) {
	store, err := OpenStore(dbPath)
	if err != nil {
		return nil, err
	}
	v, err := openVault(keyPath)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &Service{store: store, vault: v, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Close() error { return s.store.Close() }

func (s *Service) ConfigureGitHub(ctx context.Context, in GitHubConnectionInput) (GitHubConnection, error) {
	in.AccountLogin = strings.TrimSpace(in.AccountLogin)
	in.RegistryUsername = strings.TrimSpace(in.RegistryUsername)
	if Slug(in.AccountLogin) == "" || len(in.AccountLogin) > 100 || (in.AccountType != "User" && in.AccountType != "Organization") || in.AppID < 1 || in.InstallationID < 1 {
		return GitHubConnection{}, fmt.Errorf("%w: invalid GitHub connection", ErrInvalid)
	}
	if err := validateGitHubPrivateKey(in.PrivateKey); err != nil {
		return GitHubConnection{}, fmt.Errorf("%w: invalid GitHub private key", ErrInvalid)
	}
	if len(in.WebhookSecret) < 24 || len(in.WebhookSecret) > 256 || strings.ContainsAny(in.WebhookSecret, "\r\n") {
		return GitHubConnection{}, fmt.Errorf("%w: webhook secret must contain 24-256 characters", ErrInvalid)
	}
	if (in.RegistryPAT == "") != (in.RegistryUsername == "") || in.RegistryPAT != "" && (Slug(in.RegistryUsername) == "" || len(in.RegistryUsername) > 100 || len(in.RegistryPAT) < 20 || len(in.RegistryPAT) > 255 || strings.ContainsAny(in.RegistryPAT, " \t\r\n")) {
		return GitHubConnection{}, fmt.Errorf("%w: invalid registry credential", ErrInvalid)
	}
	if in.AvatarURL != "" && !validGitHubAvatarURL(in.AvatarURL) {
		return GitHubConnection{}, fmt.Errorf("%w: invalid avatar URL", ErrInvalid)
	}
	privateKey, err := s.vault.encrypt(in.PrivateKey, "github:private-key")
	if err != nil {
		return GitHubConnection{}, err
	}
	webhookSecret, err := s.vault.encrypt(in.WebhookSecret, "github:webhook-secret")
	if err != nil {
		return GitHubConnection{}, err
	}
	registryPAT := ""
	if in.RegistryPAT != "" {
		registryPAT, err = s.vault.encrypt(in.RegistryPAT, "github:registry-pat")
		if err != nil {
			return GitHubConnection{}, err
		}
	}
	now := s.now()
	id, err := s.githubConnectionID(ctx)
	if err != nil {
		return GitHubConnection{}, err
	}
	if id == "" {
		id, err = newID()
		if err != nil {
			return GitHubConnection{}, err
		}
	}
	_, err = s.store.db.ExecContext(ctx, `
INSERT INTO github_connection(singleton,id,account_login,account_type,avatar_url,app_id,installation_id,registry_username,private_key_cipher,webhook_secret_cipher,registry_pat_cipher,created_at,updated_at)
VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(singleton) DO UPDATE SET account_login=excluded.account_login,account_type=excluded.account_type,avatar_url=excluded.avatar_url,app_id=excluded.app_id,installation_id=excluded.installation_id,registry_username=excluded.registry_username,private_key_cipher=excluded.private_key_cipher,webhook_secret_cipher=excluded.webhook_secret_cipher,registry_pat_cipher=excluded.registry_pat_cipher,updated_at=excluded.updated_at`,
		id, in.AccountLogin, in.AccountType, in.AvatarURL, in.AppID, in.InstallationID, in.RegistryUsername, privateKey, webhookSecret, registryPAT, now, now)
	if err != nil {
		return GitHubConnection{}, fmt.Errorf("save GitHub connection: %w", err)
	}
	return s.GitHubConnection(ctx)
}

func (s *Service) githubConnectionID(ctx context.Context) (string, error) {
	var id string
	err := s.store.db.QueryRowContext(ctx, `SELECT id FROM github_connection WHERE singleton=1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load GitHub connection: %w", err)
	}
	return id, nil
}

func (s *Service) GitHubConnection(ctx context.Context) (GitHubConnection, error) {
	var out GitHubConnection
	var privateCipher, webhookCipher, registryCipher string
	var lastSync sql.NullTime
	err := s.store.db.QueryRowContext(ctx, `SELECT id,account_login,account_type,avatar_url,app_id,installation_id,registry_username,private_key_cipher,webhook_secret_cipher,registry_pat_cipher,last_synced_at,created_at,updated_at FROM github_connection WHERE singleton=1`).Scan(
		&out.ID, &out.AccountLogin, &out.AccountType, &out.AvatarURL, &out.AppID, &out.InstallationID, &out.RegistryUsername, &privateCipher, &webhookCipher, &registryCipher, &lastSync, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return GitHubConnection{}, ErrNotFound
	}
	if err != nil {
		return GitHubConnection{}, fmt.Errorf("load GitHub connection: %w", err)
	}
	out.PrivateKeyConfigured = privateCipher != ""
	out.WebhookConfigured = webhookCipher != ""
	out.RegistryConfigured = registryCipher != ""
	if lastSync.Valid {
		out.LastSyncedAt = lastSync.Time
	}
	return out, nil
}

func (s *Service) githubSecrets(ctx context.Context) (privateKey, webhookSecret, registryPAT string, err error) {
	var privateCipher, webhookCipher, registryCipher string
	err = s.store.db.QueryRowContext(ctx, `SELECT private_key_cipher,webhook_secret_cipher,registry_pat_cipher FROM github_connection WHERE singleton=1`).Scan(&privateCipher, &webhookCipher, &registryCipher)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	if err != nil {
		return "", "", "", fmt.Errorf("load GitHub credentials: %w", err)
	}
	privateKey, err = s.vault.decrypt(privateCipher, "github:private-key")
	if err != nil {
		return "", "", "", err
	}
	webhookSecret, err = s.vault.decrypt(webhookCipher, "github:webhook-secret")
	if err != nil {
		return "", "", "", err
	}
	if registryCipher != "" {
		registryPAT, err = s.vault.decrypt(registryCipher, "github:registry-pat")
	}
	return privateKey, webhookSecret, registryPAT, err
}

func validateGitHubPrivateKey(value string) error {
	block, _ := pem.Decode([]byte(value))
	if block == nil || len(block.Bytes) == 0 {
		return ErrInvalid
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		if key.N.BitLen() < 2048 {
			return ErrInvalid
		}
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return ErrInvalid
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return ErrInvalid
	}
	return nil
}

func validGitHubAvatarURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "avatars.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}
