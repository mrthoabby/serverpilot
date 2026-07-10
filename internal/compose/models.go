package compose

import "time"

// VolumePolicy describes how a persistent mount is handled during clone.
type VolumePolicy string

const (
	VolumePolicyCopy  VolumePolicy = "copy"
	VolumePolicyShare VolumePolicy = "share"
	VolumePolicyEmpty VolumePolicy = "empty"
)

// OperationState tracks a long-running compose operation.
type OperationState string

const (
	StateAnalyzing   OperationState = "analyzing"
	StateReserved    OperationState = "reserved"
	StateStarting    OperationState = "starting"
	StateHealthy     OperationState = "healthy"
	StatePromoting   OperationState = "promoting"
	StateActive      OperationState = "active"
	StateFailed      OperationState = "failed"
	StateRollingBack OperationState = "rolling_back"
	StateDeleting    OperationState = "deleting"
)

// Endpoint describes one public service port managed by ServerPilot.
type Endpoint struct {
	Service       string `json:"service"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
	EnvVar        string `json:"env_var"`
	HostPort      int    `json:"host_port,omitempty"`
}

// MountSpec describes a persistent mount discovered during analysis.
type MountSpec struct {
	Key         string       `json:"key"`
	Service     string       `json:"service"`
	Type        string       `json:"type"`
	Source      string       `json:"source,omitempty"`
	Destination string       `json:"destination"`
	Driver      string       `json:"driver,omitempty"`
	Supported   bool         `json:"supported"`
	Reason      string       `json:"reason,omitempty"`
	Policy      VolumePolicy `json:"policy,omitempty"`
}

// ServiceSpec is the normalized view of one compose service.
type ServiceSpec struct {
	Name         string      `json:"name"`
	Image        string      `json:"image,omitempty"`
	BuildContext string      `json:"build_context,omitempty"`
	ExposedPorts []string    `json:"exposed_ports,omitempty"`
	Endpoints    []Endpoint  `json:"endpoints,omitempty"`
	Mounts       []MountSpec `json:"mounts,omitempty"`
	InternalOnly bool        `json:"internal_only"`
}

// AnalyzeResult is returned before any mutating compose operation.
type AnalyzeResult struct {
	ProjectName string        `json:"project_name"`
	ProjectRoot string        `json:"project_root"`
	ComposeFile string        `json:"compose_file"`
	Services    []ServiceSpec `json:"services"`
	Endpoints   []Endpoint    `json:"endpoints"`
	Mounts      []MountSpec   `json:"mounts"`
	Blocking    []string      `json:"blocking,omitempty"`
	Warnings    []string      `json:"warnings,omitempty"`
	CanDeploy   bool          `json:"can_deploy"`
	Fingerprint string        `json:"fingerprint,omitempty"`
}

// Generation records one immutable deployment of a project.
type Generation struct {
	ID             string         `json:"id"`
	Number         int            `json:"number"`
	ComposeProject string         `json:"compose_project"`
	Fingerprint    string         `json:"fingerprint"`
	State          OperationState `json:"state"`
	Endpoints      []Endpoint     `json:"endpoints"`
	CreatedAt      time.Time      `json:"created_at"`
	PromotedAt     time.Time      `json:"promoted_at,omitempty"`
	RollbackOf     string         `json:"rollback_of,omitempty"`
}

// ProjectRecord is the authoritative compose project registry entry.
type ProjectRecord struct {
	Name           string       `json:"name"`
	Alias          string       `json:"alias,omitempty"`
	RootDir        string       `json:"root_dir"`
	ComposeFile    string       `json:"compose_file"`
	ActiveGenID    string       `json:"active_generation_id"`
	Generations    []Generation `json:"generations"`
	ParentOf       []string     `json:"clone_ids,omitempty"`
	CloneParentID  string       `json:"clone_parent_id,omitempty"`
	CloneParentGen string       `json:"clone_parent_generation_id,omitempty"`
	Outdated       bool         `json:"outdated,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// CloneRequest carries clone parameters from CLI or API.
type CloneRequest struct {
	ParentName   string                  `json:"parent_name"`
	CloneName    string                  `json:"clone_name"`
	Alias        string                  `json:"alias,omitempty"`
	Mounts       map[string]VolumePolicy `json:"mounts"`
	ShareConfirm bool                    `json:"share_confirm,omitempty"`
}

// DeployRequest carries deploy parameters.
type DeployRequest struct {
	Name        string `json:"name"`
	Alias       string `json:"alias,omitempty"`
	RootDir     string `json:"root_dir"`
	ComposeFile string `json:"compose_file"`
}
