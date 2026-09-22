package appmanager

import "time"

type AppType string

const (
	AppTypeNextJS  AppType = "nextjs"
	AppTypeRESTAPI AppType = "rest-api"
)

type EnvironmentType string

const (
	EnvironmentTest       EnvironmentType = "test"
	EnvironmentStaging    EnvironmentType = "staging"
	EnvironmentProduction EnvironmentType = "production"
)

type ArtifactStatus string

const (
	ArtifactWaiting  ArtifactStatus = "waiting_for_image"
	ArtifactReady    ArtifactStatus = "ready"
	ArtifactFailed   ArtifactStatus = "failed"
	ArtifactTimedOut ArtifactStatus = "timed_out"
)

type DeploymentStatus string

const (
	DeploymentQueued   DeploymentStatus = "queued"
	DeploymentRunning  DeploymentStatus = "running"
	DeploymentSuccess  DeploymentStatus = "success"
	DeploymentFailed   DeploymentStatus = "failed"
	DeploymentCanceled DeploymentStatus = "canceled"
)

type GitHubConnection struct {
	ID                   string    `json:"id"`
	AccountLogin         string    `json:"account_login"`
	AccountType          string    `json:"account_type"`
	AvatarURL            string    `json:"avatar_url,omitempty"`
	AppID                int64     `json:"app_id"`
	InstallationID       int64     `json:"installation_id"`
	RegistryUsername     string    `json:"registry_username,omitempty"`
	PrivateKeyConfigured bool      `json:"private_key_configured"`
	WebhookConfigured    bool      `json:"webhook_configured"`
	RegistryConfigured   bool      `json:"registry_configured"`
	LastSyncedAt         time.Time `json:"last_synced_at,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type Repository struct {
	ID            string    `json:"id"`
	GitHubID      int64     `json:"github_id"`
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	DefaultBranch string    `json:"default_branch"`
	Language      string    `json:"language,omitempty"`
	Private       bool      `json:"private"`
	HTMLURL       string    `json:"html_url"`
	Archived      bool      `json:"archived"`
	LastSyncedAt  time.Time `json:"last_synced_at"`
	AppCount      int       `json:"application_count"`
}

type Project struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Slug             string    `json:"slug"`
	Description      string    `json:"description,omitempty"`
	ApplicationCount int       `json:"application_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Application struct {
	ID            string        `json:"id"`
	ProjectID     *string       `json:"project_id,omitempty"`
	ProjectName   string        `json:"project_name,omitempty"`
	RepositoryID  string        `json:"repository_id"`
	Repository    string        `json:"repository"`
	Name          string        `json:"name"`
	Slug          string        `json:"slug"`
	Description   string        `json:"description,omitempty"`
	Type          AppType       `json:"type"`
	Dockerfile    string        `json:"dockerfile"`
	BuildContext  string        `json:"build_context"`
	ContainerPort int           `json:"container_port"`
	ImageName     string        `json:"image_name"`
	Environments  []Environment `json:"environments,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

type Environment struct {
	ID                string          `json:"id"`
	ApplicationID     string          `json:"application_id"`
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Type              EnvironmentType `json:"type"`
	AgentID           *string         `json:"agent_id,omitempty"`
	ContainerName     string          `json:"container_name"`
	ContainerPort     int             `json:"container_port"`
	HostPort          int             `json:"host_port,omitempty"`
	Domain            string          `json:"domain,omitempty"`
	SiteEnabled       bool            `json:"site_enabled"`
	SSLEnabled        bool            `json:"ssl_enabled"`
	HealthPath        string          `json:"health_path,omitempty"`
	AutoDeploy        bool            `json:"auto_deploy"`
	CurrentArtifactID *string         `json:"current_artifact_id,omitempty"`
	CurrentVersion    string          `json:"current_version,omitempty"`
	Status            string          `json:"status"`
	LastDeploymentAt  time.Time       `json:"last_deployment_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type ConfigurationEntry struct {
	ID        string    `json:"id"`
	OwnerType string    `json:"owner_type"`
	OwnerID   string    `json:"owner_id"`
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Secret    bool      `json:"secret"`
	HasValue  bool      `json:"has_value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ResolvedVariable struct {
	Key    string
	Value  string
	Secret bool
}

type RepositoryRelease struct {
	ID           string                       `json:"id"`
	RepositoryID string                       `json:"repository_id"`
	Tag          string                       `json:"tag"`
	CommitSHA    string                       `json:"commit_sha"`
	Name         string                       `json:"name,omitempty"`
	PublishedAt  time.Time                    `json:"published_at"`
	CreatedAt    time.Time                    `json:"created_at"`
	Artifacts    []ApplicationReleaseArtifact `json:"artifacts,omitempty"`
}

type ApplicationReleaseArtifact struct {
	ID             string         `json:"id"`
	ReleaseID      string         `json:"release_id"`
	ApplicationID  string         `json:"application_id"`
	Application    string         `json:"application"`
	ImageReference string         `json:"image_reference"`
	ImageDigest    string         `json:"image_digest,omitempty"`
	Status         ArtifactStatus `json:"status"`
	LastCheckedAt  time.Time      `json:"last_checked_at,omitempty"`
	FailureCode    string         `json:"failure_code,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type Deployment struct {
	ID            string           `json:"id"`
	EnvironmentID string           `json:"environment_id"`
	ArtifactID    string           `json:"artifact_id"`
	Status        DeploymentStatus `json:"status"`
	Trigger       string           `json:"trigger"`
	Actor         string           `json:"actor"`
	ContainerName string           `json:"container_name,omitempty"`
	ImageDigest   string           `json:"image_digest,omitempty"`
	LogSummary    string           `json:"log_summary,omitempty"`
	StartedAt     time.Time        `json:"started_at,omitempty"`
	FinishedAt    time.Time        `json:"finished_at,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
}

type Agent struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	Version         string    `json:"version,omitempty"`
	LastHeartbeatAt time.Time `json:"last_heartbeat_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Overview struct {
	Projects          int          `json:"projects"`
	Applications      int          `json:"applications"`
	UnassignedApps    int          `json:"unassigned_applications"`
	WaitingArtifacts  int          `json:"waiting_artifacts"`
	FailedDeployments int          `json:"failed_deployments"`
	ConnectedAgents   int          `json:"connected_agents"`
	RecentDeployments []Deployment `json:"recent_deployments"`
}

type CreateApplicationInput struct {
	RepositoryID  string                   `json:"repository_id"`
	ProjectID     *string                  `json:"project_id,omitempty"`
	Name          string                   `json:"name"`
	Description   string                   `json:"description,omitempty"`
	Type          AppType                  `json:"type"`
	Dockerfile    string                   `json:"dockerfile"`
	BuildContext  string                   `json:"build_context"`
	ContainerPort int                      `json:"container_port"`
	Environments  []CreateEnvironmentInput `json:"environments"`
}

type CreateEnvironmentInput struct {
	Name        string               `json:"name"`
	Type        EnvironmentType      `json:"type"`
	AgentID     *string              `json:"agent_id,omitempty"`
	Domain      string               `json:"domain,omitempty"`
	SiteEnabled bool                 `json:"site_enabled"`
	SSLEnabled  bool                 `json:"ssl_enabled"`
	HealthPath  string               `json:"health_path,omitempty"`
	AutoDeploy  bool                 `json:"auto_deploy"`
	Variables   []ConfigurationInput `json:"configuration,omitempty"`
}

type CreateProjectInput struct {
	Name           string               `json:"name"`
	Description    string               `json:"description,omitempty"`
	ApplicationIDs []string             `json:"application_ids"`
	Variables      []ConfigurationInput `json:"variables,omitempty"`
}

type ConfigurationInput struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

type GitHubConnectionInput struct {
	AccountLogin     string `json:"account_login"`
	AccountType      string `json:"account_type"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	AppID            int64  `json:"app_id"`
	InstallationID   int64  `json:"installation_id"`
	PrivateKey       string `json:"private_key"`
	WebhookSecret    string `json:"webhook_secret"`
	RegistryUsername string `json:"registry_username,omitempty"`
	RegistryPAT      string `json:"registry_pat,omitempty"`
}

// GitHubSetupInput contains only values that cannot be discovered from the
// authenticated GitHub App. Registry credentials remain optional because
// public GHCR images support anonymous pulls.
type GitHubSetupInput struct {
	AppID            int64  `json:"app_id"`
	PrivateKey       string `json:"private_key"`
	RegistryUsername string `json:"registry_username,omitempty"`
	RegistryPAT      string `json:"registry_pat,omitempty"`
}

type GitHubSetupResult struct {
	Connection    GitHubConnection `json:"connection"`
	WebhookSecret string           `json:"webhook_secret"`
}

type RepositoryInput struct {
	GitHubID      int64  `json:"github_id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	Language      string `json:"language,omitempty"`
	Private       bool   `json:"private"`
	HTMLURL       string `json:"html_url"`
	Archived      bool   `json:"archived"`
}
