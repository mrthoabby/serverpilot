package appmanager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deployhealth"
	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/mapper"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

type AgentDeploySpec struct {
	DeploymentID    string             `json:"deployment_id"`
	EnvironmentID   string             `json:"environment_id"`
	ApplicationID   string             `json:"application_id"`
	ApplicationType AppType            `json:"application_type"`
	ContainerName   string             `json:"container_name"`
	ContainerPort   int                `json:"container_port"`
	Image           string             `json:"image"`
	ImageDigest     string             `json:"image_digest"`
	Domain          string             `json:"domain,omitempty"`
	SiteEnabled     bool               `json:"site_enabled"`
	SSLEnabled      bool               `json:"ssl_enabled"`
	HealthPath      string             `json:"health_path,omitempty"`
	Variables       []ResolvedVariable `json:"variables"`
	RegistryUser    string             `json:"registry_user,omitempty"`
	RegistryToken   string             `json:"registry_token,omitempty"`
}

type AgentDeployResult struct {
	ContainerName string `json:"container_name,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
	ImageDigest   string `json:"image_digest,omitempty"`
}

func (s *Service) prepareAgentDeploySpec(ctx context.Context, deploymentID string) (AgentDeploySpec, error) {
	var environmentID, artifactID string
	if err := s.store.db.QueryRowContext(ctx, `SELECT environment_id,artifact_id FROM deployments WHERE id=? AND status='running'`, deploymentID).Scan(&environmentID, &artifactID); err != nil {
		return AgentDeploySpec{}, fmt.Errorf("load agent deployment")
	}
	env, artifact, app, err := s.artifactForDeployment(ctx, environmentID, artifactID)
	if err != nil {
		return AgentDeploySpec{}, err
	}
	image, err := deploymentImage(app.ImageName, artifact)
	if err != nil {
		return AgentDeploySpec{}, err
	}
	variables, err := s.ResolveEnvironmentVariables(ctx, environmentID)
	if err != nil {
		return AgentDeploySpec{}, err
	}
	conn, connErr := s.GitHubConnection(ctx)
	_, _, pat, secretErr := s.githubSecrets(ctx)
	if connErr != nil || secretErr != nil {
		conn.AccountLogin, pat = "", ""
	}
	return AgentDeploySpec{DeploymentID: deploymentID, EnvironmentID: env.ID, ApplicationID: app.ID, ApplicationType: app.Type, ContainerName: env.ContainerName, ContainerPort: env.ContainerPort, Image: image, ImageDigest: artifact.ImageDigest, Domain: env.Domain, SiteEnabled: env.SiteEnabled, SSLEnabled: env.SSLEnabled, HealthPath: env.HealthPath, Variables: variables, RegistryUser: conn.AccountLogin, RegistryToken: pat}, nil
}

// ExecuteAgentDeploy executes one allowlisted deployment job on the remote
// server. The spec is supplied transiently over TLS and is never persisted by
// the agent.
func ExecuteAgentDeploy(ctx context.Context, spec AgentDeploySpec) (AgentDeployResult, error) {
	if !validID(spec.DeploymentID) || !validID(spec.EnvironmentID) || !validID(spec.ApplicationID) || spec.ContainerPort < 1 || spec.ContainerPort > 65535 || !validHealthPath(spec.HealthPath) {
		return AgentDeployResult{}, fmt.Errorf("invalid deployment job")
	}
	if spec.ApplicationType != AppTypeNextJS && spec.ApplicationType != AppTypeRESTAPI {
		return AgentDeployResult{}, fmt.Errorf("invalid application type")
	}
	if spec.SiteEnabled && !validDomain(spec.Domain) {
		return AgentDeployResult{}, fmt.Errorf("invalid managed domain")
	}
	repository := spec.Image
	if at := strings.Index(repository, "@"); at >= 0 {
		repository = repository[:at]
	} else if colon := strings.LastIndex(repository, ":"); colon >= len("ghcr.io/") {
		repository = repository[:colon]
	}
	if !validImageRepository(repository) {
		return AgentDeployResult{}, fmt.Errorf("invalid managed image")
	}
	if err := pullRegistryImage(ctx, spec.RegistryUser, spec.RegistryToken, spec.Image); err != nil {
		return AgentDeployResult{}, err
	}
	envFile, cleanup, err := writeRuntimeEnvFile(spec.EnvironmentID, spec.Variables)
	if err != nil {
		return AgentDeployResult{}, err
	}
	defer cleanup()
	hostPort, err := portalloc.ReserveOwner("appmanager:"+spec.EnvironmentID, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		return AgentDeployResult{}, fmt.Errorf("reserve deployment port")
	}
	name := spec.ContainerName
	exists := managedContainerExists(ctx, name)
	if !exists && !strings.HasSuffix(name, "__blue") && !strings.HasSuffix(name, "__green") {
		name += "__blue"
	}
	if !exists {
		if err := runManagedContainer(ctx, spec, name, hostPort, envFile); err != nil {
			return AgentDeployResult{}, err
		}
	} else if spec.SiteEnabled {
		if err := docker.ReleaseBlueGreenProgress(docker.BlueGreenRequest{Container: name, Image: spec.Image, EnvFile: envFile, HealthURL: spec.HealthPath, HealthTimeout: 90 * time.Second, Drain: 10 * time.Second}, func(string) {}); err != nil {
			return AgentDeployResult{}, fmt.Errorf("blue-green deployment failed")
		}
		name = nextColorName(name)
	} else if err := replaceManagedContainer(ctx, name, spec, hostPort, envFile); err != nil {
		return AgentDeployResult{}, err
	}
	return AgentDeployResult{ContainerName: name, HostPort: hostPort, ImageDigest: spec.ImageDigest}, nil
}

func pullRegistryImage(ctx context.Context, username, token, image string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	configDir, err := os.MkdirTemp(runtimeDir, "agent-docker-config-")
	if err != nil {
		return fmt.Errorf("create registry session")
	}
	defer os.RemoveAll(configDir)
	if err := os.Chmod(configDir, 0o700); err != nil {
		return fmt.Errorf("secure registry session")
	}
	if token != "" {
		if Slug(username) == "" || strings.ContainsAny(token, " \t\r\n") {
			return fmt.Errorf("invalid registry credential")
		}
		loginCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(loginCtx, dockerBin, "--config", configDir, "login", "ghcr.io", "--username", username, "--password-stdin")
		cmd.Stdin = strings.NewReader(token + "\n")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("registry authentication failed")
		}
	}
	pullCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := exec.CommandContext(pullCtx, dockerBin, "--config", configDir, "pull", "--", image).Run(); err != nil {
		return fmt.Errorf("image pull failed")
	}
	return nil
}

func managedContainerExists(ctx context.Context, name string) bool {
	if !validManagedContainerName(name) {
		return false
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return exec.CommandContext(checkCtx, dockerBin, "inspect", "--type", "container", "--", name).Run() == nil
}

func validManagedContainerName(name string) bool {
	if len(name) < 4 || len(name) > 128 || !strings.HasPrefix(name, "sp-") {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func runManagedContainer(ctx context.Context, spec AgentDeploySpec, name string, hostPort int, envFile string) error {
	if !validManagedContainerName(name) {
		return fmt.Errorf("invalid managed container name")
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped", "--label", "io.serverpilot.managed=true", "--label", "io.serverpilot.application=" + spec.ApplicationID, "--label", "io.serverpilot.environment=" + spec.EnvironmentID, "--env-file", envFile, "-p", "127.0.0.1:" + strconv.Itoa(hostPort) + ":" + strconv.Itoa(spec.ContainerPort) + "/tcp", spec.Image}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(runCtx, dockerBin, args...).Output()
	if err != nil {
		return fmt.Errorf("container start failed")
	}
	containerID := strings.TrimSpace(string(out))
	if len(containerID) < 12 || len(containerID) > 64 || !isLowerHex(containerID) {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		return fmt.Errorf("container returned invalid id")
	}
	if err := deployhealth.WaitHealthy(deployhealth.Options{ContainerName: name, HostPort: hostPort, HealthURL: spec.HealthPath, Timeout: 90 * time.Second}); err != nil {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		return fmt.Errorf("container health check failed")
	}
	if spec.SiteEnabled {
		templateType := templates.API
		if spec.ApplicationType == AppTypeNextJS {
			templateType = templates.NextJS
		}
		_, err = sites.Create(sites.CreateRequest{ContainerID: containerID, ContainerName: name, HostPort: hostPort, ContainerPort: spec.ContainerPort, Domain: spec.Domain, Template: templateType})
		if err != nil {
			_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
			return fmt.Errorf("site activation failed")
		}
		if spec.SSLEnabled {
			if err := mapper.EnableSSL(spec.Domain); err != nil {
				_ = nginx.RemoveSiteFiles(spec.Domain)
				_ = sites.DeleteByConfigName(spec.Domain)
				_ = nginx.ReloadNginx()
				_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
				return fmt.Errorf("SSL activation failed")
			}
		}
	}
	return nil
}

func replaceManagedContainer(ctx context.Context, name string, spec AgentDeploySpec, hostPort int, envFile string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	oldName := name + "-previous-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := exec.CommandContext(ctx, dockerBin, "stop", "--time", "10", "--", name).Run(); err != nil {
		return fmt.Errorf("stop current container failed")
	}
	if err := exec.CommandContext(ctx, dockerBin, "rename", name, oldName).Run(); err != nil {
		_ = exec.Command(dockerBin, "start", name).Run()
		return fmt.Errorf("stage current container failed")
	}
	restore := func() {
		_ = exec.Command(dockerBin, "rm", "-f", "--", name).Run()
		_ = exec.Command(dockerBin, "rename", oldName, name).Run()
		_ = exec.Command(dockerBin, "start", name).Run()
	}
	if err := runManagedContainer(ctx, spec, name, hostPort, envFile); err != nil {
		restore()
		return err
	}
	if err := exec.CommandContext(ctx, dockerBin, "rm", "--", oldName).Run(); err != nil {
		return fmt.Errorf("remove previous container failed")
	}
	return nil
}
