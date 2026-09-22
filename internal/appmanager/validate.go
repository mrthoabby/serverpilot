package appmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid input")
)

func ValidateCreateApplication(in CreateApplicationInput) error {
	if !validID(in.RepositoryID) {
		return fmt.Errorf("%w: repository is required", ErrInvalid)
	}
	if in.ProjectID != nil && !validID(*in.ProjectID) {
		return fmt.Errorf("%w: invalid project", ErrInvalid)
	}
	if err := validateDisplayName(in.Name, 80); err != nil {
		return fmt.Errorf("%w: invalid application name", ErrInvalid)
	}
	if len(in.Description) > 500 {
		return fmt.Errorf("%w: description too long", ErrInvalid)
	}
	if in.Type != AppTypeNextJS && in.Type != AppTypeRESTAPI {
		return fmt.Errorf("%w: invalid application type", ErrInvalid)
	}
	if err := validateRelativeBuildPath(in.Dockerfile, false); err != nil {
		return fmt.Errorf("%w: invalid Dockerfile path", ErrInvalid)
	}
	if err := validateRelativeBuildPath(in.BuildContext, true); err != nil {
		return fmt.Errorf("%w: invalid build context", ErrInvalid)
	}
	if in.ContainerPort < 1 || in.ContainerPort > 65535 {
		return fmt.Errorf("%w: invalid container port", ErrInvalid)
	}
	if len(in.Environments) == 0 || len(in.Environments) > 30 {
		return fmt.Errorf("%w: at least one environment is required", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(in.Environments))
	for _, environment := range in.Environments {
		if err := ValidateEnvironmentInput(environment); err != nil {
			return err
		}
		slug := Slug(environment.Name)
		if _, ok := seen[slug]; ok {
			return fmt.Errorf("%w: duplicate environment name", ErrInvalid)
		}
		seen[slug] = struct{}{}
	}
	return nil
}

func ValidateEnvironmentInput(in CreateEnvironmentInput) error {
	if err := validateDisplayName(in.Name, 64); err != nil || Slug(in.Name) == "" {
		return fmt.Errorf("%w: invalid environment name", ErrInvalid)
	}
	if in.Type != EnvironmentTest && in.Type != EnvironmentStaging && in.Type != EnvironmentProduction {
		return fmt.Errorf("%w: invalid environment type", ErrInvalid)
	}
	if in.AutoDeployMode != AutoDeployManual && in.AutoDeployMode != AutoDeployTag && in.AutoDeployMode != AutoDeployRelease {
		return fmt.Errorf("%w: invalid automatic deployment mode", ErrInvalid)
	}
	if in.AgentID != nil && !validID(*in.AgentID) {
		return fmt.Errorf("%w: invalid agent", ErrInvalid)
	}
	if in.Domain != "" && !validDomain(in.Domain) {
		return fmt.Errorf("%w: invalid domain", ErrInvalid)
	}
	if in.SSLEnabled && (!in.SiteEnabled || in.Domain == "") {
		return fmt.Errorf("%w: SSL requires a managed domain", ErrInvalid)
	}
	if !validHealthPath(in.HealthPath) {
		return fmt.Errorf("%w: invalid health path", ErrInvalid)
	}
	if err := ValidateConfigurationInputs(in.Variables); err != nil {
		return err
	}
	return nil
}

func ValidateCreateProject(in CreateProjectInput) error {
	if err := validateDisplayName(in.Name, 80); err != nil {
		return fmt.Errorf("%w: invalid project name", ErrInvalid)
	}
	if len(in.Description) > 500 {
		return fmt.Errorf("%w: description too long", ErrInvalid)
	}
	if len(in.ApplicationIDs) == 0 || len(in.ApplicationIDs) > 200 {
		return fmt.Errorf("%w: at least one application is required", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(in.ApplicationIDs))
	for _, id := range in.ApplicationIDs {
		if !validID(id) {
			return fmt.Errorf("%w: invalid application", ErrInvalid)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: duplicate application", ErrInvalid)
		}
		seen[id] = struct{}{}
	}
	return ValidateConfigurationInputs(in.Variables)
}

func ValidateConfigurationInputs(entries []ConfigurationInput) error {
	if len(entries) > 500 {
		return fmt.Errorf("%w: too many configuration entries", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		totalBytes += len(entry.Key) + len(entry.Value)
		if !validEnvKey(entry.Key) || len(entry.Value) > 64*1024 || strings.ContainsAny(entry.Value, "\x00\r\n") || totalBytes > 512*1024 {
			return fmt.Errorf("%w: invalid configuration entry", ErrInvalid)
		}
		if _, ok := seen[entry.Key]; ok {
			return fmt.Errorf("%w: duplicate configuration key", ErrInvalid)
		}
		seen[entry.Key] = struct{}{}
	}
	return nil
}

// MergeVariables runs in O(p+e); environment values intentionally overwrite
// project values with the same logical key.
func MergeVariables(project, environment []ResolvedVariable) []ResolvedVariable {
	merged := make(map[string]ResolvedVariable, len(project)+len(environment))
	for _, item := range project {
		merged[item.Key] = item
	}
	for _, item := range environment {
		merged[item.Key] = item
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ResolvedVariable, 0, len(keys))
	for _, key := range keys {
		result = append(result, merged[key])
	}
	return result
}

func Slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func ImageRepository(owner, repository, application string) (string, error) {
	ownerSlug := Slug(owner)
	repoSlug := Slug(repository)
	appSlug := Slug(application)
	if ownerSlug == "" || repoSlug == "" || appSlug == "" {
		return "", fmt.Errorf("%w: invalid image components", ErrInvalid)
	}
	packageName := "sp-" + repoSlug + "-" + appSlug
	original := strings.ToLower(strings.TrimSpace(owner)) + "/" + strings.ToLower(strings.TrimSpace(repository)) + "/" + strings.ToLower(strings.TrimSpace(application))
	normalized := ownerSlug + "/" + repoSlug + "/" + appSlug
	needsSuffix := original != normalized
	if len(packageName) > 180 || needsSuffix {
		sum := sha256.Sum256([]byte(original))
		suffix := hex.EncodeToString(sum[:6])
		maxBase := 180 - 1 - len(suffix)
		if len(packageName) > maxBase {
			packageName = strings.TrimRight(packageName[:maxBase], "-")
		}
		packageName += "-" + suffix
	}
	return "ghcr.io/" + ownerSlug + "/" + packageName, nil
}

func ImageReference(imageRepository, tag, digest string) (string, error) {
	if !validImageRepository(imageRepository) {
		return "", fmt.Errorf("%w: invalid image repository", ErrInvalid)
	}
	if digest != "" {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 || !isLowerHex(digest[7:]) {
			return "", fmt.Errorf("%w: invalid image digest", ErrInvalid)
		}
		return imageRepository + "@" + digest, nil
	}
	if !validReleaseTag(tag) {
		return "", fmt.Errorf("%w: invalid release tag", ErrInvalid)
	}
	return imageRepository + ":" + tag, nil
}

func validID(value string) bool { return len(value) == 32 && isLowerHex(value) }

func isLowerHex(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return value != ""
}

func validateDisplayName(value string, max int) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return ErrInvalid
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return ErrInvalid
		}
	}
	return nil
}

func validateRelativeBuildPath(value string, allowDot bool) error {
	if value == "" || len(value) > 240 || filepath.IsAbs(value) || strings.Contains(value, "\\") {
		return ErrInvalid
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '/' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return ErrInvalid
	}
	clean := filepath.Clean(value)
	if clean == "." && allowDot {
		return nil
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return ErrInvalid
	}
	return nil
}

func validEnvKey(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if r >= 'A' && r <= 'Z' || r == '_' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func validDomain(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validHealthPath(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 256 && value[0] == '/' && !strings.ContainsAny(value, "?#\\\r\n") && !strings.Contains(value, "..")
}

func validReleaseTag(value string) bool {
	if value == "" || len(value) > 128 || value == "latest" || value[0] == '.' || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// validVersionTag intentionally accepts only semantic version tags prefixed
// with v. Other Git tags remain ordinary source-control markers and must not
// create deployable versions in ServerPilot.
func validVersionTag(value string) bool {
	if !validReleaseTag(value) || len(value) < 6 || value[0] != 'v' {
		return false
	}
	versionAndBuild := strings.Split(value[1:], "+")
	if len(versionAndBuild) > 2 || len(versionAndBuild) == 2 && !validVersionIdentifiers(versionAndBuild[1], false) {
		return false
	}
	coreAndPrerelease := strings.SplitN(versionAndBuild[0], "-", 2)
	if len(coreAndPrerelease) == 2 && !validVersionIdentifiers(coreAndPrerelease[1], true) {
		return false
	}
	parts := strings.Split(coreAndPrerelease[0], ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validVersionIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" || rejectNumericLeadingZero && len(identifier) > 1 && identifier[0] == '0' && identifierIsNumeric(identifier) {
			return false
		}
		for _, r := range identifier {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func identifierIsNumeric(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validGitCommitSHA(value string) bool {
	return (len(value) == 40 || len(value) == 64) && isLowerHex(value)
}

func validImageRepository(value string) bool {
	if !strings.HasPrefix(value, "ghcr.io/") || len(value) > 255 || strings.ContainsAny(value, "@:\\ \t\r\n") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "ghcr.io/"), "/")
	if len(parts) != 2 || parts[0] == "" || !strings.HasPrefix(parts[1], "sp-") {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
				continue
			}
			return false
		}
	}
	return true
}
