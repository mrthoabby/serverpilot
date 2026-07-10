package docker

import "strings"

const (
	labelComposeProject     = "com.docker.compose.project"
	labelComposeService     = "com.docker.compose.service"
	labelComposeConfigHash  = "com.docker.compose.config-hash"
	labelComposeWorkingDir  = "com.docker.compose.project.working_dir"
	labelComposeConfigFiles = "com.docker.compose.project.config_files"
)

// ComposeMeta holds Docker Compose metadata extracted from container labels.
type ComposeMeta struct {
	Project     string `json:"project,omitempty"`
	Service     string `json:"service,omitempty"`
	ConfigHash  string `json:"config_hash,omitempty"`
	WorkingDir  string `json:"working_dir,omitempty"`
	ConfigFiles string `json:"config_files,omitempty"`
	IsCompose   bool   `json:"is_compose"`
}

// ParseComposeLabels extracts compose metadata from Docker labels.
func ParseComposeLabels(labels map[string]string) ComposeMeta {
	if labels == nil {
		return ComposeMeta{}
	}
	project := strings.TrimSpace(labels[labelComposeProject])
	if project == "" {
		return ComposeMeta{}
	}
	return ComposeMeta{
		Project:     project,
		Service:     strings.TrimSpace(labels[labelComposeService]),
		ConfigHash:  strings.TrimSpace(labels[labelComposeConfigHash]),
		WorkingDir:  strings.TrimSpace(labels[labelComposeWorkingDir]),
		ConfigFiles: strings.TrimSpace(labels[labelComposeConfigFiles]),
		IsCompose:   true,
	}
}

// IsComposeContainer reports whether labels indicate a compose-managed container.
func IsComposeContainer(labels map[string]string) bool {
	return ParseComposeLabels(labels).IsCompose
}
