package compose

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

// PreviewClone returns the analysis needed before creating a stack clone.
func PreviewClone(parentName, cloneName string) (*AnalyzeResult, *ProjectRecord, error) {
	if err := ValidateProjectName(cloneName); err != nil {
		return nil, nil, err
	}
	parent, ok, err := GetProject(parentName)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("parent compose project not found")
	}
	analysis, err := AnalyzeProjectStrict(parent.Name, parent.RootDir, parent.ComposeFile)
	if err != nil {
		return nil, nil, err
	}
	return analysis, &parent, nil
}

// Clone creates a full isolated clone of a compose project.
func Clone(req CloneRequest, progress Progress) (*ProjectRecord, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !deps.ComposeAvailable() {
		return nil, fmt.Errorf("docker compose is not installed")
	}
	analysis, parent, err := PreviewClone(req.ParentName, req.CloneName)
	if err != nil {
		return nil, err
	}
	if !analysis.CanDeploy {
		return nil, fmt.Errorf("parent project failed policy checks")
	}
	if _, exists, err := GetProject(req.CloneName); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("clone project name already exists")
	}

	for _, mount := range analysis.Mounts {
		if !mount.Supported {
			continue
		}
		policy, ok := req.Mounts[mount.Key]
		if !ok {
			return nil, fmt.Errorf("missing volume policy for %s", mount.Key)
		}
		if policy == VolumePolicyShare && !req.ShareConfirm {
			return nil, fmt.Errorf("writable volume sharing requires explicit confirmation")
		}
	}

	parentGen, ok := GetActiveGeneration(*parent)
	if !ok {
		return nil, fmt.Errorf("parent has no active generation")
	}
	_ = parentGen

	genID, err := NewGenerationID()
	if err != nil {
		return nil, err
	}
	composeProject := req.CloneName
	progress("Reserving clone ports...")
	ownerPorts, endpoints, owners, err := reserveEndpoints(req.CloneName, genID, analysis.Endpoints)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	genDir, err := GenerationDir(req.CloneName, genID)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	cloneDataRoot := filepath.Join(parent.RootDir, "stack-clones", req.CloneName)
	if err := os.MkdirAll(cloneDataRoot, 0o750); err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	progress("Preparing clone data...")
	if err := applyVolumePolicies(parent, analysis, req, cloneDataRoot, progress); err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	envPath, err := writeDeployEnv(genDir, ownerPorts)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	overrideContent := RenderPortOverrideYAML(endpoints)
	overridePath, err := WriteOverride(genDir, "serverpilot.override.yml", overrideContent)
	if err != nil {
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	runner := Runner{
		ProjectRoot:    analysis.ProjectRoot,
		ComposeFile:    analysis.ComposeFile,
		ComposeProject: composeProject,
		ProjectEnvFile: managedEnvFile(analysis.ProjectRoot),
		EnvFile:        envPath,
		OverrideFile:   overridePath,
	}
	progress("Starting clone stack...")
	if err := runner.Up(""); err != nil {
		_ = runner.Down(false)
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	now := time.Now().UTC()
	gen := Generation{
		ID:             genID,
		Number:         1,
		ComposeProject: composeProject,
		Fingerprint:    analysis.Fingerprint,
		State:          StateActive,
		Endpoints:      endpoints,
		CreatedAt:      now,
		PromotedAt:     now,
	}
	rec := ProjectRecord{
		Name:           req.CloneName,
		Alias:          strings.TrimSpace(req.Alias),
		RootDir:        analysis.ProjectRoot,
		ComposeFile:    analysis.ComposeFile,
		ActiveGenID:    genID,
		Generations:    []Generation{gen},
		CloneParentID:  parent.Name,
		CloneParentGen: parent.ActiveGenID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := UpsertProject(rec); err != nil {
		_ = runner.Down(false)
		portalloc.ReleaseOwners(owners)
		return nil, err
	}

	parent.ParentOf = append(parent.ParentOf, req.CloneName)
	if err := UpsertProject(*parent); err != nil {
		_ = runner.Down(false)
		portalloc.ReleaseOwners(owners)
		return nil, err
	}
	_ = RefreshOutdatedFlags()
	progress("Compose clone created.")
	return &rec, nil
}

func applyVolumePolicies(parent *ProjectRecord, analysis *AnalyzeResult, req CloneRequest, cloneRoot string, progress Progress) error {
	_ = parent
	for _, mount := range analysis.Mounts {
		if !mount.Supported {
			continue
		}
		policy := req.Mounts[mount.Key]
		switch policy {
		case VolumePolicyEmpty:
			continue
		case VolumePolicyShare:
			progress("Sharing volume " + mount.Key + " (read/write risk if both stacks write)")
			continue
		case VolumePolicyCopy:
			dest := filepath.Join(cloneRoot, sanitizeKey(mount.Key))
			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return err
			}
			if mount.Type == "bind" && mount.Source != "" {
				if err := copyTree(mount.Source, dest); err != nil {
					return fmt.Errorf("failed to copy bind mount %s", mount.Key)
				}
			}
		default:
			return fmt.Errorf("unsupported volume policy for %s", mount.Key)
		}
	}
	return nil
}

func sanitizeKey(key string) string {
	key = strings.ReplaceAll(key, ":", "_")
	key = strings.ReplaceAll(key, "/", "_")
	return key
}

func copyTree(src, dest string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source is symlink")
	}
	if info.IsDir() {
		if err := os.MkdirAll(dest, 0o750); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dest, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// SyncClone redeploys an outdated clone from its parent fingerprint.
func SyncClone(cloneName string, req CloneRequest, progress Progress) (*ProjectRecord, error) {
	rec, ok, err := GetProject(cloneName)
	if err != nil {
		return nil, err
	}
	if !ok || rec.CloneParentID == "" {
		return nil, fmt.Errorf("compose clone not found")
	}
	req.CloneName = cloneName
	req.ParentName = rec.CloneParentID
	progress("Deleting outdated clone stack before resync...")
	if err := DeleteProjectStack(cloneName, progress); err != nil {
		return nil, err
	}
	return Clone(req, progress)
}
