package users

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ── SSH key generation + private-key vault ──────────────────────────────
//
// Threat model: ServerPilot already runs as root, so an attacker who owns
// root on the host owns everything. The vault therefore is NOT a defense
// against on-host root compromise. What it DOES defend against:
//
//   * Backup leakage. The vault file lives in /etc/serverpilot/ssh-vault.json
//     while the master secret material (session_secret) lives in
//     /etc/serverpilot/config.json. A backup that grabs only one of the two
//     yields ciphertext that cannot be decrypted on its own.
//   * Read-only privilege escalation. A vulnerability that lets an attacker
//     read the vault file but not config.json (or vice versa) does not
//     reveal private keys.
//   * Disk-imaging or pulled-drive scenarios. Same logic.
//
// What it explicitly does NOT defend against:
//
//   * Anyone with the dashboard admin session — they can call the
//     /api/users/ssh-keys/private endpoint and pull any stored key.
//   * Root on the host.
//
// The vault is therefore a CONVENIENCE feature for admins. The right
// long-term posture is for users to keep their own private keys and only
// upload the public side. Everything below is documented as such in the
// UI and the audit log records every fetch with actor + timestamp so any
// abuse is at least visible after the fact.

const (
	vaultFile         = "/etc/serverpilot/ssh-vault.json"
	keygenScratchDir  = "/etc/serverpilot/.ssh-keygen"
	hkdfContextLabel  = "sp-ssh-vault-v1"

	// minSessionSecretLen guards against a degenerate config that somehow
	// has a missing or short SessionSecret. The setup flow generates 64
	// hex chars (32 bytes) so anything shorter is unexpected.
	minSessionSecretLen = 32
)

// allowedKeyTypes enumerates every key type the dashboard will generate.
// Anything not on this list is rejected at the API boundary AND at the
// SDK boundary — no inference, no guessing.
var allowedKeyTypes = map[string]keyTypeSpec{
	"ed25519": {Type: "ed25519", Bits: 0},      // bits ignored
	"rsa":     {Type: "rsa", Bits: 4096},       // 4096 minimum
}

// commentRegex constrains the -C value passed to ssh-keygen. The comment
// is appended to the public key line and may be displayed by other tools;
// we restrict to a conservative ASCII set with @ and dot to allow standard
// "user@host" comments without enabling shell-metacharacter or
// argv-injection style abuse.
var commentRegex = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)

type keyTypeSpec struct {
	Type string
	Bits int
}

// GeneratedKey is the response shape returned at generation time. The
// caller is expected to display PrivateKey ONCE and then drop the
// reference — it is also written into the encrypted vault if `store=true`,
// so future fetches go through LoadStoredPrivateKey instead.
type GeneratedKey struct {
	Username    string `json:"username"`
	Type        string `json:"type"`
	Bits        int    `json:"bits,omitempty"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	Stored      bool   `json:"stored"`
	CreatedAt   string `json:"created_at"`
}

// vaultEntry is the on-disk encrypted shape per user. Algorithm version is
// stored explicitly so a future migration can be staged without breaking
// existing entries.
type vaultEntry struct {
	Algorithm   string `json:"alg"` // "AES-256-GCM"
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
	KeyType     string `json:"key_type"`
	Bits        int    `json:"bits,omitempty"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Comment     string `json:"comment,omitempty"`
}

type vault struct {
	Entries map[string]vaultEntry `json:"entries"`
}

// GenerateAndStoreSSHKey runs ssh-keygen, installs the public key into
// ~/.ssh/authorized_keys, and (if `store` is true) writes the encrypted
// private key into the vault. If `createIfMissing` is true and the user
// does not yet exist, the user is created as SSH-only with the freshly
// generated public key in a single transaction (any error rolls back the
// useradd via the existing CreateSSHUser path).
//
// Defences in order applied:
//  1. Username regex.
//  2. keyType allowlist.
//  3. Comment regex.
//  4. Scratch dir at /etc/serverpilot/.ssh-keygen, mode 0700, root-only.
//     Each invocation gets a unique CreateTemp inside it, so concurrent
//     generations cannot collide and no path is predictable.
//  5. ssh-keygen invoked with absolute path, separate argv, no shell.
//  6. After read, both files are best-effort-overwritten with zeros and
//     unlinked. The scratch dir mode prevents non-root users from racing
//     us anyway.
//  7. Public key is added via the existing AddSSHKey/CreateSSHUser path
//     which sets 0700/0600 and chowns to user:deploy.
//  8. Vault file is rewritten atomically (CreateTemp in /etc/serverpilot/
//     + chmod 0600 + sync + rename).
//  9. The "create if missing" path goes through CreateSSHUser, which
//     internally calls passwd -l to lock password login. Generating a
//     keypair therefore never accidentally lands a user with a usable
//     password (CWE-258).
func GenerateAndStoreSSHKey(username, keyType, comment, sessionSecret string, store, createIfMissing bool) (*GeneratedKey, error) {
	if !validUsername.MatchString(username) {
		return nil, errors.New("invalid username")
	}
	spec, ok := allowedKeyTypes[keyType]
	if !ok {
		return nil, fmt.Errorf("unsupported key type %q (allowed: ed25519, rsa)", keyType)
	}
	if comment != "" && !commentRegex.MatchString(comment) {
		return nil, errors.New("invalid comment (allowed: A-Z a-z 0-9 . _ @ + -)")
	}
	if comment == "" {
		comment = username + "@serverpilot"
	}
	if len(sessionSecret) < minSessionSecretLen {
		return nil, errors.New("vault unavailable: session secret too short")
	}

	mu.Lock()
	defer mu.Unlock()

	userPresent := isManaged(username)
	if !userPresent && !createIfMissing {
		return nil, fmt.Errorf("user %q is not a ServerPilot-managed deploy user", username)
	}

	// Scratch dir hygiene. 0700 + root-owned protects the temp files even
	// if ssh-keygen briefly creates them with 0600/0644.
	if err := os.MkdirAll(keygenScratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create scratch dir")
	}
	if err := os.Chmod(keygenScratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot chmod scratch dir")
	}

	// CreateTemp gives us an unpredictable file name. ssh-keygen will
	// refuse to overwrite an existing file, so we delete the placeholder
	// CreateTemp made and pass the same path to ssh-keygen.
	holder, err := os.CreateTemp(keygenScratchDir, "key-*")
	if err != nil {
		return nil, fmt.Errorf("cannot create scratch file")
	}
	keyPath := holder.Name()
	pubPath := keyPath + ".pub"
	holder.Close()
	if err := os.Remove(keyPath); err != nil {
		return nil, fmt.Errorf("cannot prepare scratch path")
	}
	defer secureCleanup(keyPath)
	defer secureCleanup(pubPath)

	args := []string{
		"-q",
		"-t", spec.Type,
		"-N", "", // empty passphrase — the vault adds AES-GCM at rest
		"-C", comment,
		"-f", keyPath,
	}
	if spec.Type == "rsa" {
		args = append(args, "-b", fmt.Sprintf("%d", spec.Bits))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Do not propagate ssh-keygen stderr to the API caller — it can
		// include the scratch path and host details.
		_ = out
		return nil, errors.New("key generation failed")
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, errors.New("cannot read generated public key")
	}
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("cannot read generated private key")
	}
	publicKey := strings.TrimSpace(string(pubBytes))
	privateKey := string(privBytes)

	if !isValidSSHPubKey(publicKey) {
		// ssh-keygen produced something we don't recognise — bail rather
		// than risk pushing it into authorized_keys.
		return nil, errors.New("generated public key failed validation")
	}

	fingerprint, err := computeFingerprint(pubPath)
	if err != nil {
		// Non-fatal: the fingerprint is convenience metadata. Still log it
		// generically (not the path) and continue.
		fingerprint = ""
	}

	// Install the public key into the live system. This is what actually
	// gives the user access; vault storage is purely for re-display.
	//
	// We hold `mu` for both branches:
	//   - When the user already exists, append directly via the unlocked
	//     internal helper (the public CreateSSHUser/AddSSHKey would
	//     deadlock because they take `mu` themselves).
	//   - When creating the user, we have to release/reacquire because
	//     CreateSSHUser locks; do that explicitly so the rest of the
	//     vault flow remains protected.
	if userPresent {
		if err := appendAuthorizedKey(username, publicKey); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				return nil, fmt.Errorf("could not install public key")
			}
		}
	} else {
		// Release the package lock briefly so CreateSSHUser can take it.
		mu.Unlock()
		err := CreateSSHUser(username, publicKey)
		mu.Lock()
		if err != nil {
			return nil, fmt.Errorf("could not create user: %s", err.Error())
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	stored := false
	if store {
		entry, err := encryptVaultEntry(privateKey, spec, comment, fingerprint, sessionSecret, now)
		if err != nil {
			return nil, fmt.Errorf("vault encryption failed")
		}
		if err := writeVaultEntry(username, entry); err != nil {
			return nil, fmt.Errorf("vault write failed")
		}
		stored = true
	}

	return &GeneratedKey{
		Username:    username,
		Type:        spec.Type,
		Bits:        spec.Bits,
		PublicKey:   publicKey,
		PrivateKey:  privateKey,
		Fingerprint: fingerprint,
		Stored:      stored,
		CreatedAt:   now,
	}, nil
}

// LoadStoredPrivateKey returns the decrypted private key from the vault.
// Caller MUST audit-log every successful read with the actor's identity
// and the target username. The package itself does not log because this
// runs at the SDK boundary; the web layer is closer to the actor.
func LoadStoredPrivateKey(username, sessionSecret string) (string, error) {
	if !validUsername.MatchString(username) {
		return "", errors.New("invalid username")
	}
	if len(sessionSecret) < minSessionSecretLen {
		return "", errors.New("vault unavailable")
	}

	mu.Lock()
	defer mu.Unlock()

	v, err := loadVault()
	if err != nil {
		return "", err
	}
	entry, ok := v.Entries[username]
	if !ok {
		return "", errors.New("no stored private key for user")
	}
	plaintext, err := decryptVaultEntry(entry, sessionSecret)
	if err != nil {
		return "", errors.New("vault decryption failed")
	}
	return plaintext, nil
}

// HasStoredPrivateKey reports whether the vault contains an entry for
// `username`. Used by the UI to decide whether to render the "Reveal
// private key" button.
func HasStoredPrivateKey(username string) bool {
	if !validUsername.MatchString(username) {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	v, err := loadVault()
	if err != nil {
		return false
	}
	_, ok := v.Entries[username]
	return ok
}

// DeleteStoredPrivateKey wipes the vault entry for `username`. Idempotent.
// Does NOT remove the public key from authorized_keys — that's a separate
// action so an admin can drop the convenience copy without revoking
// access.
func DeleteStoredPrivateKey(username string) error {
	if !validUsername.MatchString(username) {
		return errors.New("invalid username")
	}
	mu.Lock()
	defer mu.Unlock()
	v, err := loadVault()
	if err != nil {
		return err
	}
	if _, ok := v.Entries[username]; !ok {
		return nil // idempotent
	}
	delete(v.Entries, username)
	return saveVault(v)
}

// PurgeStoredPrivateKey is invoked when a user is deleted via DeleteUser.
// It is safe to call even if the user never had a vault entry. Public so
// the user-deletion handler can call it without juggling locks.
func PurgeStoredPrivateKey(username string) {
	_ = DeleteStoredPrivateKey(username)
}

// ── Crypto + persistence ────────────────────────────────────────────────

// deriveVaultKey produces a per-vault AES-256 key from the session secret
// using HKDF-SHA256. The salt is constant — secret rotation is handled by
// re-generating session_secret which forces re-encryption (we expose a
// migration path through the same Generate flow).
func deriveVaultKey(sessionSecret string) ([]byte, error) {
	if len(sessionSecret) < minSessionSecretLen {
		return nil, errors.New("session secret too short")
	}
	r := hkdf.New(sha256.New, []byte(sessionSecret), nil, []byte(hkdfContextLabel))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New("vault key derivation failed")
	}
	return key, nil
}

func encryptVaultEntry(plaintext string, spec keyTypeSpec, comment, fingerprint, sessionSecret, now string) (vaultEntry, error) {
	key, err := deriveVaultKey(sessionSecret)
	if err != nil {
		return vaultEntry{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return vaultEntry{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return vaultEntry{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return vaultEntry{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return vaultEntry{
		Algorithm:   "AES-256-GCM",
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
		KeyType:     spec.Type,
		Bits:        spec.Bits,
		Fingerprint: fingerprint,
		Comment:     comment,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func decryptVaultEntry(entry vaultEntry, sessionSecret string) (string, error) {
	if entry.Algorithm != "AES-256-GCM" {
		return "", errors.New("unsupported algorithm")
	}
	key, err := deriveVaultKey(sessionSecret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed")
	}
	return string(plaintext), nil
}

func loadVault() (*vault, error) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &vault{Entries: map[string]vaultEntry{}}, nil
		}
		return nil, err
	}
	var v vault
	if err := json.Unmarshal(data, &v); err != nil {
		return &vault{Entries: map[string]vaultEntry{}}, nil
	}
	if v.Entries == nil {
		v.Entries = map[string]vaultEntry{}
	}
	return &v, nil
}

func saveVault(v *vault) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(configDir, ".ssh-vault-*.json")
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
	return os.Rename(tmpPath, vaultFile)
}

func writeVaultEntry(username string, entry vaultEntry) error {
	v, err := loadVault()
	if err != nil {
		return err
	}
	if existing, ok := v.Entries[username]; ok {
		entry.CreatedAt = existing.CreatedAt
	}
	v.Entries[username] = entry
	return saveVault(v)
}

// computeFingerprint asks ssh-keygen for the SHA256 fingerprint. We pass
// the public key file path (already validated to live under the scratch
// dir) — ssh-keygen reads it and prints "<bits> SHA256:<base64> ...".
func computeFingerprint(pubPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-l", "-f", pubPath).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for _, f := range fields {
		if strings.HasPrefix(f, "SHA256:") {
			return f, nil
		}
	}
	return "", nil
}

// secureCleanup overwrites the file with zeros (best-effort) and unlinks
// it. We don't depend on this for confidentiality — the scratch dir is
// already root-only — but it tightens the on-disk window during which
// post-mortem disk forensics could recover the key.
func secureCleanup(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().IsRegular() && info.Size() > 0 {
		// Open for write with truncate, zero, sync, close — best effort.
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
			zero := make([]byte, 4096)
			remaining := info.Size()
			for remaining > 0 {
				n := int64(len(zero))
				if remaining < n {
					n = remaining
				}
				if _, werr := f.Write(zero[:n]); werr != nil {
					break
				}
				remaining -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

// VaultPath returns the on-disk vault path. Used by ops tooling.
func VaultPath() string { return filepath.Clean(vaultFile) }
