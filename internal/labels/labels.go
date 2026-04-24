package labels

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Label represents the type assigned to a container.
type Label string

const (
	LabelAPI    Label = "api"
	LabelNestJS Label = "nestjs"
	LabelBack   Label = "back"
)

// labelsFile stores labels alongside the main serverpilot config.
const labelsFile = "/etc/serverpilot/labels.json"

var (
	mu     sync.RWMutex
	cache  map[string]Label // container name -> label
	loaded bool
)

// ValidLabel returns true if the given string is one of the allowed labels.
func ValidLabel(l string) bool {
	switch Label(l) {
	case LabelAPI, LabelNestJS, LabelBack:
		return true
	}
	return false
}

// load reads the labels file into the in-memory cache. Call with mu held.
func load() error {
	if loaded {
		return nil
	}
	cache = make(map[string]Label)

	data, err := os.ReadFile(labelsFile)
	if err != nil {
		if os.IsNotExist(err) {
			loaded = true
			return nil // no file yet — start empty
		}
		return fmt.Errorf("failed to read labels file: %w", err)
	}

	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("failed to parse labels file: %w", err)
	}
	loaded = true
	return nil
}

// save persists the in-memory cache to disk. Call with mu held.
func save() error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}
	if err := os.WriteFile(labelsFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write labels file: %w", err)
	}
	return nil
}

// ensureLoaded must be called with mu held (read or write).
// On first call, it loads from disk. Subsequent calls are no-ops.
func ensureLoaded() error {
	if loaded {
		return nil
	}
	return load()
}

// GetAll returns all container labels.
func GetAll() (map[string]Label, error) {
	mu.Lock()
	defer mu.Unlock()

	if err := ensureLoaded(); err != nil {
		return nil, err
	}

	// Return a copy.
	cp := make(map[string]Label, len(cache))
	for k, v := range cache {
		cp[k] = v
	}
	return cp, nil
}

// Get returns the label for a specific container. Returns "" if none set.
func Get(containerName string) (Label, error) {
	mu.Lock()
	defer mu.Unlock()

	if err := ensureLoaded(); err != nil {
		return "", err
	}
	return cache[containerName], nil
}

// Set assigns a label to a container, replacing any existing one.
func Set(containerName string, label Label) error {
	if !ValidLabel(string(label)) {
		return fmt.Errorf("invalid label: %s", label)
	}

	mu.Lock()
	defer mu.Unlock()

	if err := ensureLoaded(); err != nil {
		return err
	}

	cache[containerName] = label
	return save()
}

// Remove removes the label from a container.
func Remove(containerName string) error {
	mu.Lock()
	defer mu.Unlock()

	if err := ensureLoaded(); err != nil {
		return err
	}

	delete(cache, containerName)
	return save()
}
