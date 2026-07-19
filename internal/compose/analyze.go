package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type rawCompose struct {
	Services map[string]rawService `yaml:"services"`
	Include  []string              `yaml:"include"`
	Networks map[string]rawNetwork `yaml:"networks"`
}

type rawNetwork struct {
	External bool   `yaml:"external"`
	Name     string `yaml:"name"`
}

type rawService struct {
	Image         string   `yaml:"image"`
	Build         any      `yaml:"build"`
	Restart       string   `yaml:"restart"`
	Ports         []any    `yaml:"ports"`
	Expose        []any    `yaml:"expose"`
	Volumes       []string `yaml:"volumes"`
	Environment   any      `yaml:"environment"`
	NetworkMode   string   `yaml:"network_mode"`
	Privileged    bool     `yaml:"privileged"`
	CapAdd        []string `yaml:"cap_add"`
	Devices       []string `yaml:"devices"`
	Pid           string   `yaml:"pid"`
	Ipc           string   `yaml:"ipc"`
	Secrets       any      `yaml:"secrets"`
	Configs       any      `yaml:"configs"`
	ContainerName string   `yaml:"container_name"`
	Networks      any      `yaml:"networks"`
}

// AnalyzeProject reads and policy-checks a compose project without mutating state.
func AnalyzeProject(name, rootDir, composeFile string) (*AnalyzeResult, error) {
	if err := ValidateProjectName(name); err != nil {
		return nil, err
	}
	root, err := ResolveProjectRoot(rootDir)
	if err != nil {
		return nil, err
	}
	file, err := ResolveComposeFile(root, composeFile)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("compose file not found")
	}
	if info.Size() > maxComposeFileBytes {
		return nil, fmt.Errorf("compose file is too large")
	}
	rawBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file")
	}

	var doc rawCompose
	if err := yaml.Unmarshal(rawBytes, &doc); err != nil {
		return nil, fmt.Errorf("invalid compose yaml")
	}
	if len(doc.Services) == 0 {
		return nil, fmt.Errorf("compose file has no services")
	}
	if len(doc.Services) > maxServicesPerProject {
		return nil, fmt.Errorf("too many services")
	}
	for _, inc := range doc.Include {
		if issue := CheckInclude(inc); issue != nil && issue.Blocking {
			return nil, fmt.Errorf("%s", issue.Message)
		}
	}

	result := &AnalyzeResult{
		ProjectName: name,
		ProjectRoot: root,
		ComposeFile: file,
	}

	serviceNames := make([]string, 0, len(doc.Services))
	for svc := range doc.Services {
		serviceNames = append(serviceNames, svc)
	}
	sortStrings(serviceNames)

	for _, svcName := range serviceNames {
		raw := doc.Services[svcName]
		if err := ValidateServiceName(svcName); err != nil {
			result.Blocking = append(result.Blocking, "invalid service name "+svcName)
			continue
		}
		ApplyRawServicePolicy(result, svcName, raw)
		spec := analyzeService(root, svcName, raw, doc.Networks)
		result.Services = append(result.Services, spec)
		result.Endpoints = append(result.Endpoints, spec.Endpoints...)
		result.Mounts = append(result.Mounts, spec.Mounts...)
	}

	if len(result.Endpoints) > maxEndpointsPerProject {
		result.Blocking = append(result.Blocking, "too many public endpoints")
	}

	result.Fingerprint = fingerprintAnalyze(result)
	result.CanDeploy = len(result.Blocking) == 0
	if len(result.Endpoints) == 1 {
		result.Endpoints[0].EnvVar = DefaultEndpointEnvVar
	}
	return result, nil
}

func analyzeService(projectRoot, name string, raw rawService, networks map[string]rawNetwork) ServiceSpec {
	spec := ServiceSpec{Name: name}

	if issue := CheckPrivileged(raw.Privileged); issue != nil {
		// surfaced via analyze blocking in caller extension if needed
		_ = issue
	}
	if issue := CheckNetworkMode(raw.NetworkMode); issue != nil && issue.Blocking {
		spec.InternalOnly = true
	}
	if raw.ContainerName != "" {
		spec.InternalOnly = true // explicit names complicate clone isolation
	}
	if issue := CheckImageReference(raw.Image); issue != nil && issue.Blocking {
		spec.InternalOnly = true
	}
	spec.Image = strings.TrimSpace(raw.Image)
	spec.Restart = strings.TrimSpace(raw.Restart)
	spec.OneShot = strings.EqualFold(spec.Restart, "no")

	if raw.Build != nil {
		ctx, _, issues := analyzeBuild(projectRoot, raw.Build)
		spec.BuildContext = ctx
		for _, msg := range issues {
			_ = msg
		}
	}

	for _, cap := range raw.CapAdd {
		_ = CheckCapability(cap)
	}
	if len(raw.Devices) > 0 {
		spec.InternalOnly = true
	}
	if strings.EqualFold(raw.Pid, "host") || strings.EqualFold(raw.Ipc, "host") {
		spec.InternalOnly = true
	}

	for _, exp := range raw.Expose {
		cp := normalizeContainerPort(exp)
		if cp != "" {
			spec.ExposedPorts = append(spec.ExposedPorts, cp)
		}
	}

	for _, p := range raw.Ports {
		ep, internal, issues := analyzePortMapping(name, p)
		for _, msg := range issues {
			_ = msg
		}
		if ep != nil {
			spec.Endpoints = append(spec.Endpoints, *ep)
		}
		if internal {
			spec.InternalOnly = spec.InternalOnly || len(spec.Endpoints) == 0
		}
	}

	for idx, vol := range raw.Volumes {
		mount := analyzeVolume(projectRoot, name, idx, vol)
		spec.Mounts = append(spec.Mounts, mount)
	}
	for _, networkName := range composeNetworkRefs(raw.Networks) {
		network, ok := networks[networkName]
		if !ok {
			spec.InternalOnly = true
			continue
		}
		spec.Networks = append(spec.Networks, NetworkSpec{
			Name:        networkName,
			RuntimeName: strings.TrimSpace(network.Name),
			External:    network.External,
		})
	}

	if len(spec.Endpoints) == 0 {
		spec.InternalOnly = true
	}
	return spec
}

func composeNetworkRefs(raw any) []string {
	var refs []string
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if name, ok := item.(string); ok && strings.TrimSpace(name) != "" {
				refs = append(refs, strings.TrimSpace(name))
			}
		}
	case map[string]interface{}:
		for name := range value {
			if strings.TrimSpace(name) != "" {
				refs = append(refs, strings.TrimSpace(name))
			}
		}
	}
	sortStrings(refs)
	return refs
}

func analyzeBuild(projectRoot string, build any) (contextPath, dockerfile string, issues []string) {
	switch v := build.(type) {
	case string:
		contextPath = strings.TrimSpace(v)
	case map[string]any:
		if c, ok := v["context"].(string); ok {
			contextPath = strings.TrimSpace(c)
		}
		if df, ok := v["dockerfile"].(string); ok {
			dockerfile = strings.TrimSpace(df)
		}
	default:
		issues = append(issues, "unsupported build definition")
		return "", "", issues
	}
	if contextPath == "" {
		contextPath = "."
	}
	if _, err := ResolveContainedPath(projectRoot, contextPath); err != nil {
		issues = append(issues, "build context escapes project root")
	}
	if dockerfile != "" {
		if _, err := ResolveContainedPath(projectRoot, filepath.Join(contextPath, dockerfile)); err != nil {
			issues = append(issues, "dockerfile escapes project root")
		}
	}
	return contextPath, dockerfile, issues
}

func analyzePortMapping(service string, raw any) (*Endpoint, bool, []string) {
	var issues []string
	switch v := raw.(type) {
	case int:
		return &Endpoint{
			Service:       service,
			ContainerPort: strconv.Itoa(v),
			Protocol:      "tcp",
			EnvVar:        EndpointEnvVar(service, strconv.Itoa(v)),
		}, false, issues
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil, true, issues
		}
		// Reject hardcoded host:container mappings; only SP env interpolation allowed.
		if !strings.Contains(s, "${") && (strings.Contains(s, ":") || regexp.MustCompile(`^\d+$`).MatchString(s)) {
			issues = append(issues, "hardcoded host ports must use ${SP_COMPOSE_PORT} variables")
			return nil, true, issues
		}
		cp, proto := splitPortProto(s)
		if cp == "" {
			return nil, true, issues
		}
		return &Endpoint{
			Service:       service,
			ContainerPort: cp,
			Protocol:      proto,
			EnvVar:        EndpointEnvVar(service, cp),
		}, strings.Contains(s, "${"), issues
	default:
		return nil, true, issues
	}
}

func analyzeVolume(projectRoot, service string, idx int, spec string) MountSpec {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) < 2 {
		return MountSpec{
			Key:       fmt.Sprintf("%s:%d", service, idx),
			Service:   service,
			Type:      "invalid",
			Supported: false,
			Reason:    "invalid volume syntax",
		}
	}
	src := strings.TrimSpace(parts[0])
	dest := strings.TrimSpace(parts[1])
	key := fmt.Sprintf("%s:%s:%s", service, src, dest)
	mount := MountSpec{
		Key:         key,
		Service:     service,
		Destination: dest,
	}
	if strings.HasPrefix(src, "/") {
		mount.Type = "bind"
		mount.Source = src
		if issue := CheckHostBind(src); issue != nil {
			mount.Supported = false
			mount.Reason = issue.Message
			return mount
		}
		if _, err := ResolveContainedPath(projectRoot, src); err != nil {
			mount.Supported = false
			mount.Reason = "bind mount must stay under project root"
			return mount
		}
		mount.Supported = true
		return mount
	}
	mount.Type = "volume"
	mount.Source = src
	mount.Driver = "local"
	mount.Supported = true
	return mount
}

func normalizeContainerPort(raw any) string {
	switch v := raw.(type) {
	case int:
		return strconv.Itoa(v) + "/tcp"
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return ""
		}
		if !strings.Contains(s, "/") {
			return s + "/tcp"
		}
		return s
	default:
		return ""
	}
}

func splitPortProto(value string) (string, string) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "${")
	value = strings.TrimSuffix(value, "}")
	if idx := strings.Index(value, "/"); idx >= 0 {
		return value[:idx], value[idx+1:]
	}
	if strings.Contains(value, ":") {
		parts := strings.Split(value, ":")
		return parts[len(parts)-1], "tcp"
	}
	return value, "tcp"
}

func fingerprintAnalyze(res *AnalyzeResult) string {
	payload, _ := json.Marshal(res)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1] > items[j]; j-- {
			items[j-1], items[j] = items[j], items[j-1]
		}
	}
}

// MergePolicyIssues aggregates blocking messages into AnalyzeResult.
func MergePolicyIssues(res *AnalyzeResult, issues ...*PolicyIssue) {
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		if issue.Blocking {
			res.Blocking = append(res.Blocking, issue.Message)
			res.CanDeploy = false
		} else {
			res.Warnings = append(res.Warnings, issue.Message)
		}
	}
}

// ApplyRawServicePolicy runs managed-production checks on a parsed service.
func ApplyRawServicePolicy(res *AnalyzeResult, svcName string, raw rawService) {
	if issue := CheckPrivileged(raw.Privileged); issue != nil {
		MergePolicyIssues(res, issue)
	}
	if issue := CheckNetworkMode(raw.NetworkMode); issue != nil {
		MergePolicyIssues(res, issue)
	}
	if len(raw.Devices) > 0 {
		MergePolicyIssues(res, &PolicyIssue{Blocking: true, Message: "devices are not allowed for service " + svcName})
	}
	if strings.EqualFold(raw.Pid, "host") {
		MergePolicyIssues(res, &PolicyIssue{Blocking: true, Message: "pid: host is not allowed for service " + svcName})
	}
	if strings.EqualFold(raw.Ipc, "host") {
		MergePolicyIssues(res, &PolicyIssue{Blocking: true, Message: "ipc: host is not allowed for service " + svcName})
	}
	for _, cap := range raw.CapAdd {
		if issue := CheckCapability(cap); issue != nil {
			MergePolicyIssues(res, issue)
		}
	}
	for _, p := range raw.Ports {
		if s, ok := p.(string); ok && !strings.Contains(s, "${SP_COMPOSE_PORT") {
			if strings.Contains(s, ":") || regexp.MustCompile(`^\d+$`).MatchString(strings.TrimSpace(s)) {
				MergePolicyIssues(res, &PolicyIssue{
					Blocking: true,
					Message:  "service " + svcName + " must use ${SP_COMPOSE_PORT...} for published ports",
				})
			}
		}
	}
}

// AnalyzeProjectStrict applies managed policy on top of structural analysis.
func AnalyzeProjectStrict(name, rootDir, composeFile string) (*AnalyzeResult, error) {
	res, err := AnalyzeProject(name, rootDir, composeFile)
	if err != nil {
		return nil, err
	}
	rawBytes, err := os.ReadFile(res.ComposeFile)
	if err != nil {
		return nil, err
	}
	var doc rawCompose
	if err := yaml.Unmarshal(rawBytes, &doc); err != nil {
		return nil, err
	}
	for svcName, raw := range doc.Services {
		ApplyRawServicePolicy(res, svcName, raw)
	}
	if len(res.Endpoints) == 1 {
		res.Endpoints[0].EnvVar = DefaultEndpointEnvVar
	}
	res.Fingerprint = fingerprintAnalyze(res)
	res.CanDeploy = len(res.Blocking) == 0
	return res, nil
}
