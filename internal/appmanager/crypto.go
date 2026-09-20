package appmanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const masterKeySize = 32

type vault struct {
	aead cipher.AEAD
}

func openVault(path string) (*vault, error) {
	key, err := loadOrCreateMasterKey(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize secret encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize secret encryption mode: %w", err)
	}
	return &vault{aead: aead}, nil
}

func loadOrCreateMasterKey(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("master key path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create secret directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("master key permissions are unsafe")
		}
		key, readErr := io.ReadAll(io.LimitReader(f, masterKeySize+1))
		if readErr != nil || len(key) != masterKeySize {
			return nil, fmt.Errorf("master key is invalid")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("open master key: %w", err)
	}

	key := make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".master-key-*")
	if err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secure master key: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sync master key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close master key: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return loadOrCreateMasterKey(path)
		}
		return nil, fmt.Errorf("install master key: %w", err)
	}
	return key, nil
}

func (v *vault) encrypt(plaintext string, context string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}
	sealed := v.aead.Seal(nil, nonce, []byte(plaintext), []byte(context))
	payload := append(nonce, sealed...)
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func (v *vault) decrypt(encoded string, context string) (string, error) {
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(payload) < v.aead.NonceSize()+v.aead.Overhead() {
		return "", fmt.Errorf("encrypted value is invalid")
	}
	nonce := payload[:v.aead.NonceSize()]
	ciphertext := payload[v.aead.NonceSize():]
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, []byte(context))
	if err != nil {
		return "", fmt.Errorf("encrypted value authentication failed")
	}
	return string(plaintext), nil
}
