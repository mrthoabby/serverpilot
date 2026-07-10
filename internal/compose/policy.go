package compose

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxServicesPerProject  = 32
	maxEndpointsPerProject = 16
	maxComposeFileBytes    = 2 * 1024 * 1024
)

var (
	dangerousHostPrefixes = []string{
		"/etc",
		"/proc",
		"/sys",
		"/dev",
		"/root",
		"/var/run/docker.sock",
		"/run/docker.sock",
	}
	dangerousNetworkModes = map[string]bool{
		"host":      true,
		"none":      false, // allowed but no publish
		"container": true,
	}
	forbiddenCapPattern = regexp.MustCompile(`(?i)^(SYS_|NET_|DAC_|ALL)`)
)

// PolicyIssue describes one policy violation.
type PolicyIssue struct {
	Blocking bool
	Message  string
}

// CheckHostBind rejects dangerous host bind sources.
func CheckHostBind(source string) *PolicyIssue {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil
	}
	clean := filepath.Clean(source)
	for _, prefix := range dangerousHostPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(filepath.Separator)) {
			return &PolicyIssue{Blocking: true, Message: "dangerous host bind: " + clean}
		}
	}
	if clean == "/" {
		return &PolicyIssue{Blocking: true, Message: "root filesystem bind is not allowed"}
	}
	return nil
}

// CheckNetworkMode validates compose network mode.
func CheckNetworkMode(mode string) *PolicyIssue {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "bridge" || strings.HasPrefix(mode, "sp-") {
		return nil
	}
	if dangerous, ok := dangerousNetworkModes[mode]; ok && dangerous {
		return &PolicyIssue{Blocking: true, Message: "network mode " + mode + " is not allowed"}
	}
	if strings.Contains(mode, ":") {
		return &PolicyIssue{Blocking: true, Message: "custom container network mode is not allowed"}
	}
	return nil
}

// CheckCapability rejects elevated capabilities.
func CheckCapability(cap string) *PolicyIssue {
	cap = strings.TrimSpace(cap)
	if cap == "" {
		return nil
	}
	if forbiddenCapPattern.MatchString(cap) {
		return &PolicyIssue{Blocking: true, Message: "capability " + cap + " is not allowed"}
	}
	return nil
}

// CheckPrivileged rejects privileged services.
func CheckPrivileged(privileged bool) *PolicyIssue {
	if privileged {
		return &PolicyIssue{Blocking: true, Message: "privileged services are not allowed"}
	}
	return nil
}

// CheckImageReference rejects remote build contexts and suspicious image refs.
func CheckImageReference(image string) *PolicyIssue {
	image = strings.TrimSpace(image)
	if image == "" {
		return nil
	}
	lower := strings.ToLower(image)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "git@") {
		return &PolicyIssue{Blocking: true, Message: "remote image references are not allowed"}
	}
	return nil
}

// CheckInclude rejects remote compose includes.
func CheckInclude(path string) *PolicyIssue {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return &PolicyIssue{Blocking: true, Message: "remote compose includes are not allowed"}
	}
	return nil
}

// EndpointEnvVar returns the SP_COMPOSE_PORT env var for a service endpoint.
func EndpointEnvVar(service, containerPort string) string {
	service = strings.ToUpper(strings.ReplaceAll(service, "-", "_"))
	port := strings.SplitN(containerPort, "/", 1)[0]
	port = strings.ReplaceAll(port, "/", "_")
	if service == "" || port == "" {
		return "SP_COMPOSE_PORT"
	}
	return fmt.Sprintf("SP_COMPOSE_PORT_%s_%s", service, port)
}

// DefaultEndpointEnvVar is used when a project exposes exactly one endpoint.
const DefaultEndpointEnvVar = "SP_COMPOSE_PORT"
