// Package cases manages server "cases" — annotated notes or configuration scenarios
// that an operator tags as either public (shareable) or private (sensitive).
// Cases are stored as a JSON file under /etc/serverpilot/.
package cases

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Visibility controls who can see a case.
type Visibility string

const (
	Public  Visibility = "public"
	Private Visibility = "private"
)

// Case is a single server scenario/note entry.
type Case struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Visibility  Visibility `json:"visibility"`
	Tags        []string   `json:"tags"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

const casesFile = "/etc/serverpilot/cases.json"

const (
	maxTitleLen = 120
	maxDescLen  = 4000
	maxTagLen   = 40
	maxTags     = 10
)

// controlCharRe strips ASCII control characters to prevent log/JSON injection.
var controlCharRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

var (
	mu     sync.RWMutex
	loaded bool
	store  []*Case
)

// newID generates a 16-byte (32-hex-char) cryptographically random identifier.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// sanitize strips control characters and trims whitespace.
func sanitize(s string, maxLen int) string {
	s = controlCharRe.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		// Trim by rune boundary to avoid splitting multibyte chars.
		runes := []rune(s)
		if len(runes) > maxLen {
			s = string(runes[:maxLen])
		}
	}
	return s
}

// ValidateVisibility returns true for "public" or "private".
func ValidateVisibility(v string) bool {
	return v == string(Public) || v == string(Private)
}

// load reads the cases file into memory. Must be called with mu held for writing.
func load() error {
	if loaded {
		return nil
	}
	store = []*Case{}

	data, err := os.ReadFile(casesFile)
	if err != nil {
		if os.IsNotExist(err) {
			loaded = true
			return nil
		}
		return fmt.Errorf("failed to read cases file: %w", err)
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return fmt.Errorf("failed to parse cases file: %w", err)
	}
	loaded = true
	return nil
}

// save writes the in-memory store to disk atomically. Must be called with mu held.
func save() error {
	if err := os.MkdirAll("/etc/serverpilot", 0750); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cases: %w", err)
	}
	// Write to a temp file first, then rename — atomic on Linux.
	tmpPath := casesFile + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0640); err != nil {
		return fmt.Errorf("failed to write cases temp file: %w", err)
	}
	if err := os.Rename(tmpPath, casesFile); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename cases file: %w", err)
	}
	return nil
}

// List returns all cases, optionally filtered by visibility.
// Pass an empty string to get all cases.
func List(filterVisibility string) ([]*Case, error) {
	mu.RLock()
	defer mu.RUnlock()
	if err := load(); err != nil {
		return nil, err
	}
	if filterVisibility == "" {
		out := make([]*Case, len(store))
		copy(out, store)
		return out, nil
	}
	var out []*Case
	for _, c := range store {
		if string(c.Visibility) == filterVisibility {
			out = append(out, c)
		}
	}
	return out, nil
}

// Get returns a single case by ID.
func Get(id string) (*Case, error) {
	mu.RLock()
	defer mu.RUnlock()
	if err := load(); err != nil {
		return nil, err
	}
	for _, c := range store {
		if c.ID == id {
			cp := *c
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("case not found: %s", id)
}

// CreateRequest holds the fields accepted when creating a case.
type CreateRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Visibility  string   `json:"visibility"` // "public" | "private"
	Tags        []string `json:"tags"`
}

// Create validates, sanitizes, and persists a new case.
func Create(req CreateRequest) (*Case, error) {
	title := sanitize(req.Title, maxTitleLen)
	if title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if !ValidateVisibility(req.Visibility) {
		return nil, fmt.Errorf("visibility must be 'public' or 'private'")
	}

	desc := sanitize(req.Description, maxDescLen)

	// Sanitize tags: drop empties, enforce per-tag length, cap total count.
	var tags []string
	for _, t := range req.Tags {
		t = sanitize(t, maxTagLen)
		if t != "" {
			tags = append(tags, t)
		}
		if len(tags) >= maxTags {
			break
		}
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	c := &Case{
		ID:          id,
		Title:       title,
		Description: desc,
		Visibility:  Visibility(req.Visibility),
		Tags:        tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mu.Lock()
	defer mu.Unlock()
	if err := load(); err != nil {
		return nil, err
	}
	store = append(store, c)
	if err := save(); err != nil {
		// Roll back the append.
		store = store[:len(store)-1]
		return nil, err
	}
	cp := *c
	return &cp, nil
}

// UpdateRequest holds mutable fields for updating a case.
type UpdateRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Visibility  string   `json:"visibility"`
	Tags        []string `json:"tags"`
}

// Update modifies an existing case by ID.
func Update(id string, req UpdateRequest) (*Case, error) {
	title := sanitize(req.Title, maxTitleLen)
	if title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if !ValidateVisibility(req.Visibility) {
		return nil, fmt.Errorf("visibility must be 'public' or 'private'")
	}

	mu.Lock()
	defer mu.Unlock()
	if err := load(); err != nil {
		return nil, err
	}

	var target *Case
	for _, c := range store {
		if c.ID == id {
			target = c
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("case not found: %s", id)
	}

	// Snapshot for rollback.
	prev := *target

	target.Title = title
	target.Description = sanitize(req.Description, maxDescLen)
	target.Visibility = Visibility(req.Visibility)
	target.UpdatedAt = time.Now().UTC()

	var tags []string
	for _, t := range req.Tags {
		t = sanitize(t, maxTagLen)
		if t != "" {
			tags = append(tags, t)
		}
		if len(tags) >= maxTags {
			break
		}
	}
	target.Tags = tags

	if err := save(); err != nil {
		*target = prev // rollback
		return nil, err
	}
	cp := *target
	return &cp, nil
}

// Delete removes a case by ID.
func Delete(id string) error {
	mu.Lock()
	defer mu.Unlock()
	if err := load(); err != nil {
		return err
	}

	idx := -1
	for i, c := range store {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("case not found: %s", id)
	}

	removed := store[idx]
	store = append(store[:idx], store[idx+1:]...)
	if err := save(); err != nil {
		// Restore.
		newStore := make([]*Case, len(store)+1)
		copy(newStore, store[:idx])
		newStore[idx] = removed
		copy(newStore[idx+1:], store[idx:])
		store = newStore
		return err
	}
	return nil
}
