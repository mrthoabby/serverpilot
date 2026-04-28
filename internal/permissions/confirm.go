package permissions

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Confirm-token flow:
//
//   1. UI calls POST /api/permissions/confirm-token with the operation
//      parameters (action, target_user, target_app or capability).
//   2. Server returns a fresh random token + TTL. The token is bound to
//      the EXACT operation it authorises, so it cannot be replayed for a
//      different grant.
//   3. UI calls the actual grant endpoint with `confirm_token: "<value>"`.
//   4. Server validates the token (constant-time compare on the random
//      bytes; equality on the bound parameters), consumes it (single-use),
//      and proceeds.
//
// Required only for grants the system flags as `dangerous` (Docker group,
// or any future sudoers rule that materially expands privilege). Cheap
// grants like nginx-reload do not require confirmation.

const (
	confirmTokenTTL = 60 * time.Second
	confirmTokenLen = 32 // bytes; emitted as 64 hex chars
)

type confirmKey struct {
	Action     string // "fs.grant" / "group.grant" / "sudoers.grant"
	Username   string
	App        string // managed app for FS grants, system app for group grants ("" for sudoers)
	Capability string // capability slug ("" for FS grants, the level itself for FS dangerous would go here)
}

type confirmEntry struct {
	token   string
	expires time.Time
}

var (
	confirmMu    sync.Mutex
	confirmStore = map[confirmKey]confirmEntry{}
)

// IssueConfirmToken creates a fresh single-use confirmation token bound to
// (action, username, app, capability). Returns the token and the TTL the
// UI should display.
func (s *Service) IssueConfirmToken(action, username, app, capability string) (string, time.Duration, error) {
	if action == "" || username == "" {
		return "", 0, errors.New("action and username are required")
	}
	raw := make([]byte, confirmTokenLen)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, errors.New("failed to generate confirm token")
	}
	token := hex.EncodeToString(raw)

	key := confirmKey{Action: action, Username: username, App: app, Capability: capability}

	confirmMu.Lock()
	defer confirmMu.Unlock()
	now := time.Now()
	// Garbage-collect expired tokens opportunistically — keeps the map
	// small without needing a goroutine.
	for k, v := range confirmStore {
		if now.After(v.expires) {
			delete(confirmStore, k)
		}
	}
	confirmStore[key] = confirmEntry{
		token:   token,
		expires: now.Add(confirmTokenTTL),
	}
	return token, confirmTokenTTL, nil
}

// ValidateAndConsumeConfirmToken returns nil iff the token matches the
// stored value for (action, username, app, capability) AND has not
// expired. The token is removed on success — single use.
//
// Constant-time comparison prevents a timing-based oracle for valid
// tokens.
func (s *Service) ValidateAndConsumeConfirmToken(action, username, app, capability, presented string) error {
	if presented == "" {
		return ErrConfirmTokenRequired
	}
	key := confirmKey{Action: action, Username: username, App: app, Capability: capability}
	confirmMu.Lock()
	defer confirmMu.Unlock()
	entry, ok := confirmStore[key]
	if !ok {
		return ErrInvalidConfirmToken
	}
	if time.Now().After(entry.expires) {
		delete(confirmStore, key)
		return ErrInvalidConfirmToken
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(presented)) != 1 {
		return ErrInvalidConfirmToken
	}
	delete(confirmStore, key) // single use
	return nil
}
