package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// ReleaseRequest updates one service image in an existing managed project.
type ReleaseRequest struct {
	Name          string
	Service       string
	ComposeFile   string // relative to /opt/<name>/, default docker-compose.yml
	ImageRef      string
	RegistryUser  string
	RegistryToken string
}

// ReleaseService pulls IMAGE_REF and recreates only the target service.
func ReleaseService(req ReleaseRequest, progress Progress) error {
	if progress == nil {
		progress = func(string) {}
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := ValidateProjectName(req.Name); err != nil {
		return err
	}
	req.Service = strings.TrimSpace(req.Service)
	if req.Service == "" {
		req.Service = "app"
	}
	if err := ValidateServiceName(req.Service); err != nil {
		return err
	}
	req.ImageRef = strings.TrimSpace(req.ImageRef)
	if req.ImageRef == "" {
		return fmt.Errorf("IMAGE_REF is required")
	}
	if !deps.ComposeAvailable() {
		return fmt.Errorf("docker compose is not installed — install docker-compose-plugin (sp setup or dashboard → Apps → Server Dependencies)")
	}

	rec, ok, err := GetProject(req.Name)
	if err != nil {
		return err
	}
	if !ok {
		composeFile := normalizeComposeFile(req.ComposeFile)
		if !managedComposeReady(req.Name, composeFile) {
			return fmt.Errorf("compose project %q not found — add %s under /opt/%s/ (and prod.env) before the first release", req.Name, composeFile, req.Name)
		}
		if !managedProdEnvExists(req.Name) {
			return fmt.Errorf("compose project %q not found — create prod.env or .env under /opt/%s/ before the first release", req.Name, req.Name)
		}
		if err := tryBootstrapManagedProject(req, progress); err != nil {
			return fmt.Errorf("first-release bootstrap failed: %w", err)
		}
		rec, ok, err = GetProject(req.Name)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("compose project %q not found after bootstrap", req.Name)
		}
	}
	gen, hasGen := GetActiveGeneration(rec)
	if !hasGen {
		return fmt.Errorf("compose project %q has no active generation", req.Name)
	}
	genDir, err := GenerationDir(req.Name, gen.ID)
	if err != nil {
		return err
	}
	envPath := filepath.Join(genDir, "serverpilot.env")
	overridePath := filepath.Join(genDir, "serverpilot.override.yml")

	cleanupLogin, err := ephemeralRegistryLogin(req.RegistryUser, req.RegistryToken)
	if err != nil {
		return err
	}
	if cleanupLogin != nil {
		defer cleanupLogin()
	}

	runner := Runner{
		ProjectRoot:    rec.RootDir,
		ComposeFile:    rec.ComposeFile,
		ComposeProject: gen.ComposeProject,
		ProjectEnvFile: managedEnvFile(rec.RootDir),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
	}
	progress("Pulling image for service " + req.Service + "...")
	if err := runner.PullService(req.Service, req.ImageRef); err != nil {
		return err
	}
	progress("Recreating service " + req.Service + " (--no-deps)...")
	if err := runner.UpServiceNoDeps(req.Service, req.ImageRef); err != nil {
		return err
	}
	progress("Release complete.")
	return nil
}

func ephemeralRegistryLogin(user, token string) (func(), error) {
	user = strings.TrimSpace(user)
	if user == "" {
		user = strings.TrimSpace(os.Getenv("REGISTRY_USER"))
	}
	token = strings.TrimSpace(token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("REGISTRY_TOKEN"))
	}
	if user == "" || token == "" {
		return nil, nil
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}
	cfgDir, err := os.MkdirTemp("", "sp-docker-config-*")
	if err != nil {
		return nil, err
	}
	tokFile, err := os.CreateTemp("", "sp-registry-token-*")
	if err != nil {
		_ = os.RemoveAll(cfgDir)
		return nil, err
	}
	tokPath := tokFile.Name()
	if _, err := tokFile.WriteString(token); err != nil {
		_ = tokFile.Close()
		_ = os.Remove(tokPath)
		_ = os.RemoveAll(cfgDir)
		return nil, err
	}
	if err := tokFile.Chmod(0o600); err != nil {
		_ = tokFile.Close()
		_ = os.Remove(tokPath)
		_ = os.RemoveAll(cfgDir)
		return nil, err
	}
	if err := tokFile.Close(); err != nil {
		_ = os.Remove(tokPath)
		_ = os.RemoveAll(cfgDir)
		return nil, err
	}

	login := exec.Command(dockerBin, "login", "ghcr.io", "-u", user, "--password-stdin")
	login.Env = append(os.Environ(), "DOCKER_CONFIG="+cfgDir)
	login.Stdin, _ = os.Open(tokPath)
	if _, err := login.CombinedOutput(); err != nil {
		_ = os.Remove(tokPath)
		_ = os.RemoveAll(cfgDir)
		return nil, fmt.Errorf("registry login failed")
	}

	cleanup := func() {
		logout := exec.Command(dockerBin, "logout", "ghcr.io")
		logout.Env = append(os.Environ(), "DOCKER_CONFIG="+cfgDir)
		_ = logout.Run()
		_ = os.Remove(tokPath)
		_ = os.RemoveAll(cfgDir)
	}
	return cleanup, nil
}
