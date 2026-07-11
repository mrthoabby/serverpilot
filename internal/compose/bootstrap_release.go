package compose

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errManagedComposeMissing = errors.New("managed compose file not found")

// tryBootstrapManagedProject registers and starts a stack from /opt/<name>/<composeFile>
// when the project is not yet in the ServerPilot registry.
func tryBootstrapManagedProject(req ReleaseRequest, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	composeFile := normalizeComposeFile(req.ComposeFile)
	root := filepath.Join(ManagedAppsRoot, req.Name)
	if _, err := ResolveComposeFile(root, composeFile); err != nil {
		return fmt.Errorf("%w: %v", errManagedComposeMissing, err)
	}
	progress("First release: bootstrapping compose project from " + filepath.Join(root, composeFile) + "...")
	_, err := Deploy(DeployRequest{
		Name:          req.Name,
		RootDir:       root,
		ComposeFile:   composeFile,
		AppImageRef:   req.ImageRef,
		RegistryUser:  req.RegistryUser,
		RegistryToken: req.RegistryToken,
	}, progress)
	return err
}

func normalizeComposeFile(file string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return "docker-compose.yml"
	}
	return file
}

func managedComposeReady(name, composeFile string) bool {
	root := filepath.Join(ManagedAppsRoot, name)
	_, err := ResolveComposeFile(root, normalizeComposeFile(composeFile))
	return err == nil
}

// managedProdEnvExists reports whether prod.env or .env exists in the project root.
func managedProdEnvExists(name string) bool {
	return managedEnvFile(filepath.Join(ManagedAppsRoot, name)) != ""
}

// managedEnvFile returns prod.env or .env under a project root when present.
func managedEnvFile(root string) string {
	for _, file := range []string{"prod.env", ".env"} {
		path := filepath.Join(root, file)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
			continue
		}
		return path
	}
	return ""
}
