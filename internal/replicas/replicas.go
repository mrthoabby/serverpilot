package replicas

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
	"github.com/mrthoabby/serverpilot/internal/labels"
	"github.com/mrthoabby/serverpilot/internal/nginx"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
)

const (
	registryDir      = "/var/lib/serverpilot"
	registryFile     = "/var/lib/serverpilot/container-replicas.json"
	replicaDataRoot  = "/opt"
	maxReplicas      = 3
	readinessTimeout = 45 * time.Second
)

var (
	mu          sync.Mutex
	nameRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	aliasRegex  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,39}$`)
	envKeyRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	certRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
)

// Progress receives user-facing operation messages for SSE handlers.
type Progress func(string)

// Replica describes one ServerPilot-managed clone of a Docker container.
type Replica struct {
	ParentID          string        `json:"parent_id"`
	ParentName        string        `json:"parent_name"`
	Name              string        `json:"name"`
	ContainerID       string        `json:"container_id,omitempty"`
	SnapshotImage     string        `json:"snapshot_image,omitempty"`
	Alias             string        `json:"alias"`
	TemplateType      string        `json:"template_type"`
	HostPort          int           `json:"host_port"`
	ContainerPort     string        `json:"container_port"`
	Protocol          string        `json:"protocol"`
	Domain            string        `json:"domain,omitempty"`
	DataDir           string        `json:"data_dir"`
	Mounts            []CopiedMount `json:"mounts,omitempty"`
	ParentFingerprint string        `json:"parent_fingerprint"`
	Status            string        `json:"status"`
	LastSyncedAt      time.Time     `json:"last_synced_at"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	Outdated          bool          `json:"outdated"`
}

type CopiedMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	CopyPath    string `json:"copy_path"`
	ReadWrite   bool   `json:"read_write"`
}

type Preview struct {
	ParentID          string         `json:"parent_id"`
	ParentName        string         `json:"parent_name"`
	Image             string         `json:"image"`
	Env               []EnvVar       `json:"env"`
	ReplicaEnv        []EnvVar       `json:"replica_env,omitempty"`
	Ports             []PortPreview  `json:"ports"`
	Mounts            []MountPreview `json:"mounts"`
	TemplateType      string         `json:"template_type"`
	ParentFingerprint string         `json:"parent_fingerprint"`
	ExistingReplicas  int            `json:"existing_replicas"`
	MaxReplicas       int            `json:"max_replicas"`
}

type EnvVar struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
}

type PortPreview struct {
	HostPort      string `json:"host_port,omitempty"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type MountPreview struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
	Supported   bool   `json:"supported"`
	Reason      string `json:"reason,omitempty"`
}

type CreateRequest struct {
	ParentID     string   `json:"parent_id"`
	Name         string   `json:"name"`
	Alias        string   `json:"alias"`
	TemplateType string   `json:"template_type"`
	Env          []string `json:"env"`
}

type SyncRequest struct {
	Name string   `json:"name"`
	Env  []string `json:"env,omitempty"`
}

type DeleteRequest struct {
	Name string `json:"name"`
}

type UpdateRequest struct {
	Name         string `json:"name"`
	Alias        string `json:"alias"`
	TemplateType string `json:"template_type"`
}

type registry struct {
	Replicas []Replica `json:"replicas"`
}

type inspectData struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Config  struct {
		Hostname     string            `json:"Hostname"`
		Image        string            `json:"Image"`
		Env          []string          `json:"Env"`
		Cmd          []string          `json:"Cmd"`
		Entrypoint   []string          `json:"Entrypoint"`
		WorkingDir   string            `json:"WorkingDir"`
		User         string            `json:"User"`
		ExposedPorts map[string]any    `json:"ExposedPorts"`
		Labels       map[string]string `json:"Labels"`
		Healthcheck  *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode   string `json:"NetworkMode"`
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
		Driver      string `json:"Driver"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func PreviewParent(parentID string) (*Preview, error) {
	return PreviewParentForReplica(parentID, "")
}

func PreviewParentForReplica(parentID, replicaName string) (*Preview, error) {
	parent, err := inspectContainer(parentID)
	if err != nil {
		return nil, err
	}
	reg := loadRegistry()
	count := 0
	for _, r := range reg.Replicas {
		if r.ParentID == parent.ID || r.ParentName == containerName(parent.Name) {
			count++
		}
	}
	fp, err := Fingerprint(parent)
	if err != nil {
		return nil, err
	}
	preview := &Preview{
		ParentID:          parent.ID,
		ParentName:        containerName(parent.Name),
		Image:             parent.Config.Image,
		Env:               splitEnv(parent.Config.Env),
		Ports:             previewPorts(parent),
		Mounts:            previewMounts(parent),
		TemplateType:      inferTemplate(parent),
		ParentFingerprint: fp,
		ExistingReplicas:  count,
		MaxReplicas:       maxReplicas,
	}
	replicaName = strings.TrimSpace(replicaName)
	if replicaName != "" {
		if !validName(replicaName) {
			return nil, fmt.Errorf("invalid replica name")
		}
		replica, err := inspectContainer(replicaName)
		if err != nil {
			return nil, fmt.Errorf("inspect replica: %w", err)
		}
		preview.ReplicaEnv = splitEnv(replica.Config.Env)
	}
	return preview, nil
}

func List() ([]Replica, error) {
	mu.Lock()
	defer mu.Unlock()

	reg := loadRegistry()
	for i := range reg.Replicas {
		_ = syncReplicaLabel(reg.Replicas[i])
		parent, err := inspectReplicaParent(&reg.Replicas[i], nil)
		if err != nil {
			reg.Replicas[i].Outdated = true
			continue
		}
		fp, err := Fingerprint(parent)
		reg.Replicas[i].Outdated = err != nil || fp != reg.Replicas[i].ParentFingerprint
		reg.Replicas[i].Status = containerStatus(reg.Replicas[i].Name)
		if domain := findDomainByPort(reg.Replicas[i].HostPort); domain != "" {
			reg.Replicas[i].Domain = domain
		}
	}
	_ = saveRegistry(reg)
	return append([]Replica(nil), reg.Replicas...), nil
}

func Create(req CreateRequest, progress Progress) (*Replica, error) {
	mu.Lock()
	defer mu.Unlock()

	if err := validateCreate(req); err != nil {
		return nil, err
	}
	parent, err := inspectContainer(req.ParentID)
	if err != nil {
		return nil, err
	}
	parentName := containerName(parent.Name)
	reg := loadRegistry()
	if replicaByName(reg, req.Name) != nil {
		return nil, fmt.Errorf("replica name already exists")
	}
	if countReplicas(reg, parent.ID, parentName) >= maxReplicas {
		return nil, fmt.Errorf("container already has %d replicas", maxReplicas)
	}
	if containerExists(req.Name) {
		return nil, fmt.Errorf("docker container with that name already exists")
	}

	portOwner := replicaPortOwner(req.Name)
	hostPort, err := portalloc.ReserveOwner(portOwner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		return nil, fmt.Errorf("reserve host port: %w", err)
	}
	created := false
	defer func() {
		if !created {
			_ = portalloc.ReleaseOwner(portOwner)
		}
	}()
	port, err := primaryContainerPort(parent)
	if err != nil {
		return nil, err
	}

	fp, err := Fingerprint(parent)
	if err != nil {
		return nil, err
	}
	dataDir := replicaDir(parentName, req.Name)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("prepare replica data dir: %w", err)
	}
	mounts, err := copyMounts(parent, parentName, req.Name)
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, err
	}

	image := snapshotImageName(parentName, req.Name)
	if err := dockerCommit(parent.ID, image, progress); err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	if err := dockerRun(parent, req.Name, image, req.Env, hostPort, port.ContainerPort, mounts, progress); err != nil {
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	if err := waitReady(req.Name, hostPort, hasHealthcheck(parent)); err != nil {
		_ = dockerRemove(req.Name, true)
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(dataDir)
		return nil, err
	}

	now := time.Now().UTC()
	replica := Replica{
		ParentID:          parent.ID,
		ParentName:        parentName,
		Name:              req.Name,
		ContainerID:       inspectID(req.Name),
		SnapshotImage:     image,
		Alias:             req.Alias,
		TemplateType:      req.TemplateType,
		HostPort:          hostPort,
		ContainerPort:     port.ContainerPort,
		Protocol:          port.Protocol,
		DataDir:           dataDir,
		Mounts:            mounts,
		ParentFingerprint: fp,
		Status:            containerStatus(req.Name),
		LastSyncedAt:      now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	reg.Replicas = append(reg.Replicas, replica)
	if err := syncReplicaLabel(replica); err != nil {
		_ = dockerRemove(req.Name, true)
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	if err := saveRegistry(reg); err != nil {
		_ = dockerRemove(req.Name, true)
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(dataDir)
		_ = labels.Remove(replica.Name)
		return nil, err
	}
	created = true
	return &replica, nil
}

func Sync(req SyncRequest, progress Progress) (*Replica, error) {
	mu.Lock()
	defer mu.Unlock()

	if !validName(req.Name) {
		return nil, fmt.Errorf("invalid replica name")
	}
	reg := loadRegistry()
	idx := replicaIndexByName(reg, req.Name)
	if idx < 0 {
		return nil, fmt.Errorf("replica not found")
	}
	old := reg.Replicas[idx]
	if progress != nil {
		progress("Inspecting parent container " + old.ParentName + "...")
	}
	parent, err := inspectReplicaParent(&old, progress)
	if err != nil {
		return nil, fmt.Errorf("inspect parent container: %w", err)
	}
	env := req.Env
	if len(env) == 0 {
		env = parent.Config.Env
	}
	if err := validateEnv(env); err != nil {
		return nil, fmt.Errorf("validate replacement environment: %w", err)
	}
	previousPort := old.HostPort

	tempName := old.Name + "-sp-sync-" + strconv.FormatInt(time.Now().Unix(), 10)
	tempDir := replicaDir(old.ParentName, tempName)
	if progress != nil {
		progress("Preparing blue-green replacement directory...")
	}
	if err := os.MkdirAll(tempDir, 0o750); err != nil {
		return nil, fmt.Errorf("prepare temp replica dir: %w", err)
	}
	if progress != nil {
		progress("Copying parent mounts into replacement data directory...")
	}
	mounts, err := copyMountsTo(parent, old.ParentName, tempName)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("copy parent mounts: %w", err)
	}
	image := snapshotImageName(old.ParentName, tempName)
	if err := dockerCommit(parent.ID, image, progress); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	portOwner := replicaPortOwner(old.Name)
	if progress != nil {
		progress("Reserving replacement port...")
	}
	newPort, err := portalloc.ReserveOwner(portOwner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("reserve replacement port: %w", err)
	}
	promoted := false
	defer func() {
		if !promoted {
			_ = portalloc.AssignOwnerPort(portOwner, previousPort)
		}
	}()
	if err := dockerRun(parent, tempName, image, env, newPort, old.ContainerPort, mounts, progress); err != nil {
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	if err := waitReady(tempName, newPort, hasHealthcheck(parent)); err != nil {
		_ = dockerRemove(tempName, true)
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	changedSites, err := switchNginxPort(old.HostPort, newPort)
	if err != nil {
		_ = dockerRemove(tempName, true)
		_ = dockerRemoveImage(image)
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	if len(changedSites) > 0 {
		if err := nginx.ReloadNginx(); err != nil {
			_, _ = switchNginxPort(newPort, old.HostPort)
			_ = nginx.ReloadNginx()
			_ = dockerRemove(tempName, true)
			_ = dockerRemoveImage(image)
			_ = os.RemoveAll(tempDir)
			return nil, fmt.Errorf("nginx reload failed; old replica kept")
		}
	}

	_ = dockerRemove(old.Name, true)
	if old.SnapshotImage != "" {
		_ = dockerRemoveImage(old.SnapshotImage)
	}
	_ = os.RemoveAll(old.DataDir)
	if err := dockerRename(tempName, old.Name); err != nil {
		return nil, fmt.Errorf("replacement is running but rename failed: %w", err)
	}
	finalDir := replicaDir(old.ParentName, old.Name)
	_ = os.RemoveAll(finalDir)
	_ = os.Rename(tempDir, finalDir)

	fp, _ := Fingerprint(parent)
	now := time.Now().UTC()
	old.ContainerID = inspectID(old.Name)
	old.ParentID = parent.ID
	old.ParentName = containerName(parent.Name)
	old.SnapshotImage = image
	old.HostPort = newPort
	old.Mounts = rewriteMountPaths(mounts, tempName, old.Name)
	old.DataDir = finalDir
	old.ParentFingerprint = fp
	old.Status = containerStatus(old.Name)
	old.Outdated = false
	old.LastSyncedAt = now
	old.UpdatedAt = now
	if domain := findDomainByPort(newPort); domain != "" {
		old.Domain = domain
	}
	reg.Replicas[idx] = old
	if err := saveRegistry(reg); err != nil {
		return nil, err
	}
	_ = syncReplicaLabel(old)
	promoted = true
	return &old, nil
}

func Delete(req DeleteRequest, progress Progress) error {
	mu.Lock()
	defer mu.Unlock()

	if !validName(req.Name) {
		return fmt.Errorf("invalid replica name")
	}
	reg := loadRegistry()
	idx := replicaIndexByName(reg, req.Name)
	if idx < 0 {
		return fmt.Errorf("replica not found")
	}
	rep := reg.Replicas[idx]
	if progress != nil {
		progress("Removing Nginx sites associated with replica port...")
	}
	if err := deleteNginxSitesByPort(rep.HostPort, progress); err != nil {
		return err
	}
	if progress != nil {
		progress("Removing replica container " + rep.Name + "...")
	}
	_ = dockerRemove(rep.Name, true)
	if rep.SnapshotImage != "" {
		_ = dockerRemoveImage(rep.SnapshotImage)
	}
	if rep.DataDir != "" {
		_ = os.RemoveAll(rep.DataDir)
	}
	reg.Replicas = append(reg.Replicas[:idx], reg.Replicas[idx+1:]...)
	_ = labels.Remove(rep.Name)
	_ = portalloc.ReleaseOwner(replicaPortOwner(rep.Name))
	return saveRegistry(reg)
}

func Update(req UpdateRequest) (*Replica, error) {
	mu.Lock()
	defer mu.Unlock()

	if !validName(req.Name) {
		return nil, fmt.Errorf("invalid replica name")
	}
	if !aliasRegex.MatchString(req.Alias) {
		return nil, fmt.Errorf("invalid alias")
	}
	if !validTemplate(req.TemplateType) {
		return nil, fmt.Errorf("invalid template type")
	}
	reg := loadRegistry()
	idx := replicaIndexByName(reg, req.Name)
	if idx < 0 {
		return nil, fmt.Errorf("replica not found")
	}
	previous := reg.Replicas[idx]
	reg.Replicas[idx].Alias = req.Alias
	reg.Replicas[idx].TemplateType = req.TemplateType
	reg.Replicas[idx].UpdatedAt = time.Now().UTC()
	if err := saveRegistry(reg); err != nil {
		return nil, err
	}
	if err := syncReplicaLabel(reg.Replicas[idx]); err != nil {
		reg.Replicas[idx] = previous
		_ = saveRegistry(reg)
		_ = syncReplicaLabel(previous)
		return nil, err
	}
	rep := reg.Replicas[idx]
	return &rep, nil
}

func syncReplicaLabel(rep Replica) error {
	if rep.Name == "" {
		return fmt.Errorf("replica name is required")
	}
	if !labels.ValidLabel(rep.TemplateType) {
		return fmt.Errorf("invalid replica label")
	}
	return labels.Set(rep.Name, labels.Label(rep.TemplateType))
}

func Fingerprint(in inspectData) (string, error) {
	relevant := struct {
		Image        string
		Env          []string
		Cmd          []string
		Entrypoint   []string
		WorkingDir   string
		User         string
		ExposedPorts []string
		Mounts       []string
		Restart      string
		NetworkMode  string
	}{
		Image:       in.Config.Image,
		Env:         append([]string(nil), in.Config.Env...),
		Cmd:         in.Config.Cmd,
		Entrypoint:  in.Config.Entrypoint,
		WorkingDir:  in.Config.WorkingDir,
		User:        in.Config.User,
		Restart:     in.HostConfig.RestartPolicy.Name,
		NetworkMode: in.HostConfig.NetworkMode,
	}
	sort.Strings(relevant.Env)
	for p := range in.Config.ExposedPorts {
		relevant.ExposedPorts = append(relevant.ExposedPorts, p)
	}
	sort.Strings(relevant.ExposedPorts)
	for _, m := range in.Mounts {
		relevant.Mounts = append(relevant.Mounts, m.Type+"|"+m.Destination+"|"+strconv.FormatBool(m.RW))
	}
	sort.Strings(relevant.Mounts)
	data, err := json.Marshal(relevant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateCreate(req CreateRequest) error {
	if !validName(req.ParentID) && !looksLikeContainerID(req.ParentID) {
		return fmt.Errorf("invalid parent container")
	}
	if !validName(req.Name) {
		return fmt.Errorf("invalid replica name")
	}
	if !aliasRegex.MatchString(req.Alias) {
		return fmt.Errorf("invalid alias")
	}
	if !validTemplate(req.TemplateType) {
		return fmt.Errorf("invalid template type")
	}
	return validateEnv(req.Env)
}

func validateEnv(env []string) error {
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if !ok || !envKeyRegex.MatchString(key) {
			return fmt.Errorf("invalid environment variable")
		}
	}
	return nil
}

func validName(name string) bool { return nameRegex.MatchString(strings.TrimSpace(name)) }

func validTemplate(t string) bool {
	switch t {
	case "api", "nestjs", "nextjs", "frontend", "minio", "gd-app", "back":
		return true
	default:
		return false
	}
}

func replicaPortOwner(name string) string {
	return "replica:" + name
}

func looksLikeContainerID(id string) bool {
	if len(id) < 12 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func inspectContainer(idOrName string) (inspectData, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return inspectData{}, err
	}
	if !validName(idOrName) && !looksLikeContainerID(idOrName) {
		return inspectData{}, fmt.Errorf("invalid container")
	}
	cmd := exec.Command(dockerBin, "inspect", idOrName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return inspectData{}, fmt.Errorf("inspect container %q: %w", idOrName, err)
		}
		return inspectData{}, fmt.Errorf("inspect container %q: %s", idOrName, detail)
	}
	var list []inspectData
	if err := json.Unmarshal(out, &list); err != nil {
		return inspectData{}, fmt.Errorf("parse inspect: %w", err)
	}
	if len(list) == 0 {
		return inspectData{}, fmt.Errorf("container not found")
	}
	return list[0], nil
}

func inspectReplicaParent(rep *Replica, progress Progress) (inspectData, error) {
	if rep == nil {
		return inspectData{}, fmt.Errorf("replica not found")
	}
	if strings.TrimSpace(rep.ParentID) != "" {
		parent, err := inspectContainer(rep.ParentID)
		if err == nil {
			rep.ParentID = parent.ID
			rep.ParentName = containerName(parent.Name)
			return parent, nil
		}
		if strings.TrimSpace(rep.ParentName) == "" {
			return inspectData{}, err
		}
		if progress != nil {
			progress("Parent container ID changed or is unavailable; retrying by parent name " + rep.ParentName + "...")
		}
	}
	parent, err := inspectContainer(rep.ParentName)
	if err != nil {
		return inspectData{}, err
	}
	rep.ParentID = parent.ID
	rep.ParentName = containerName(parent.Name)
	return parent, nil
}

func dockerCommit(containerID, image string, progress Progress) error {
	if progress != nil {
		progress("Creating snapshot image from parent...")
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	cmd := exec.Command(dockerBin, "commit", containerID, image)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker commit failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerRun(parent inspectData, name, image string, env []string, hostPort int, containerPort string, mounts []CopiedMount, progress Progress) error {
	if progress != nil {
		progress("Starting replica container " + name + "...")
	}
	if len(parent.Config.Entrypoint) > 1 {
		return fmt.Errorf("parent entrypoint has multiple argv entries; cannot safely recreate with docker CLI")
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := BuildRunArgs(parent, name, image, env, hostPort, containerPort, mounts)
	cmd := exec.Command(dockerBin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker run failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func BuildRunArgs(parent inspectData, name, image string, env []string, hostPort int, containerPort string, mounts []CopiedMount) []string {
	args := []string{"run", "-d", "--name", name}
	if parent.Config.User != "" {
		args = append(args, "--user", parent.Config.User)
	}
	if parent.Config.WorkingDir != "" {
		args = append(args, "--workdir", parent.Config.WorkingDir)
	}
	if parent.HostConfig.RestartPolicy.Name != "" && parent.HostConfig.RestartPolicy.Name != "no" {
		restart := parent.HostConfig.RestartPolicy.Name
		if restart == "on-failure" && parent.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			restart += ":" + strconv.Itoa(parent.HostConfig.RestartPolicy.MaximumRetryCount)
		}
		args = append(args, "--restart", restart)
	}
	if parent.HostConfig.NetworkMode != "" && parent.HostConfig.NetworkMode != "default" && parent.HostConfig.NetworkMode != "bridge" {
		args = append(args, "--network", parent.HostConfig.NetworkMode)
	}
	for _, item := range env {
		args = append(args, "-e", item)
	}
	if hostPort > 0 && containerPort != "" {
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:%s", hostPort, containerPort))
	}
	for _, m := range mounts {
		mode := "ro"
		if m.ReadWrite {
			mode = "rw"
		}
		args = append(args, "-v", m.CopyPath+":"+m.Destination+":"+mode)
	}
	if len(parent.Config.Entrypoint) == 1 {
		args = append(args, "--entrypoint", parent.Config.Entrypoint[0])
	}
	args = append(args, image)
	args = append(args, parent.Config.Cmd...)
	return args
}

func waitReady(name string, hostPort int, healthcheck bool) error {
	deadline := time.Now().Add(readinessTimeout)
	for time.Now().Before(deadline) {
		if healthcheck {
			status := inspectHealthStatus(name)
			if status == "healthy" {
				return nil
			}
			if status == "unhealthy" {
				return fmt.Errorf("container healthcheck failed")
			}
		} else if containerStatus(name) == "running" && tcpReady(hostPort) {
			return nil
		}
		time.Sleep(750 * time.Millisecond)
	}
	return fmt.Errorf("replica did not become ready in time")
}

func inspectHealthStatus(name string) string {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return ""
	}
	cmd := exec.Command(dockerBin, "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{end}}", name)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func tcpReady(port int) bool {
	if port <= 0 {
		return true
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 750*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func hasHealthcheck(parent inspectData) bool {
	return parent.Config.Healthcheck != nil && len(parent.Config.Healthcheck.Test) > 0
}

func dockerRemove(name string, force bool) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	args := []string{"rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)
	return exec.Command(dockerBin, args...).Run()
}

func dockerRename(oldName, newName string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	if out, err := exec.Command(dockerBin, "rename", oldName, newName).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerRemoveImage(image string) error {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return err
	}
	return exec.Command(dockerBin, "image", "rm", image).Run()
}

func inspectID(name string) string {
	in, err := inspectContainer(name)
	if err != nil {
		return ""
	}
	return in.ID
}

func containerStatus(name string) string {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return "unknown"
	}
	cmd := exec.Command(dockerBin, "inspect", "--format", "{{.State.Status}}", name)
	out, err := cmd.Output()
	if err != nil {
		return "missing"
	}
	return strings.TrimSpace(string(out))
}

func containerExists(name string) bool {
	return containerStatus(name) != "missing"
}

func primaryContainerPort(parent inspectData) (PortPreview, error) {
	ports := previewPorts(parent)
	if len(ports) == 0 {
		return PortPreview{}, fmt.Errorf("parent has no exposed or published port to clone")
	}
	for _, p := range ports {
		if p.Protocol == "tcp" {
			return p, nil
		}
	}
	return PortPreview{}, fmt.Errorf("parent has no tcp port to clone")
}

func previewPorts(parent inspectData) []PortPreview {
	seen := map[string]bool{}
	var out []PortPreview
	for key, bindings := range parent.NetworkSettings.Ports {
		cPort, proto := splitDockerPort(key)
		host := ""
		for _, b := range bindings {
			if b.HostPort != "" {
				host = b.HostPort
				break
			}
		}
		seen[key] = true
		out = append(out, PortPreview{HostPort: host, ContainerPort: cPort, Protocol: proto})
	}
	for key := range parent.Config.ExposedPorts {
		if seen[key] {
			continue
		}
		cPort, proto := splitDockerPort(key)
		out = append(out, PortPreview{ContainerPort: cPort, Protocol: proto})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerPort < out[j].ContainerPort })
	return out
}

func splitDockerPort(value string) (string, string) {
	parts := strings.SplitN(value, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return value, "tcp"
}

func previewMounts(parent inspectData) []MountPreview {
	var out []MountPreview
	for _, m := range parent.Mounts {
		mp := MountPreview{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			ReadWrite:   m.RW,
			Supported:   m.Type == "bind" || (m.Type == "volume" && (m.Driver == "" || m.Driver == "local")),
		}
		if !mp.Supported {
			mp.Reason = "only local bind mounts and local Docker volumes can be cloned independently"
		}
		out = append(out, mp)
	}
	return out
}

func splitEnv(env []string) []EnvVar {
	var out []EnvVar
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		out = append(out, EnvVar{Key: key, Value: value, Sensitive: looksSensitive(key)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func looksSensitive(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") ||
		strings.Contains(k, "token") || strings.Contains(k, "key")
}

func inferTemplate(parent inspectData) string {
	image := strings.ToLower(parent.Config.Image)
	if strings.Contains(image, "next") {
		return "nextjs"
	}
	return "api"
}

func copyMounts(parent inspectData, parentName, replicaName string) ([]CopiedMount, error) {
	return copyMountsTo(parent, parentName, replicaName)
}

func copyMountsTo(parent inspectData, parentName, replicaName string) ([]CopiedMount, error) {
	var out []CopiedMount
	for i, m := range parent.Mounts {
		if m.Type != "bind" && !(m.Type == "volume" && (m.Driver == "" || m.Driver == "local")) {
			return nil, fmt.Errorf("mount %s uses unsupported type/driver", m.Destination)
		}
		src, err := filepath.EvalSymlinks(m.Source)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect mount source")
		}
		info, err := os.Lstat(src)
		if err != nil {
			return nil, fmt.Errorf("cannot stat mount source")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("mount source symlink refused")
		}
		dest := filepath.Join(replicaDir(parentName, replicaName), "mounts", fmt.Sprintf("m%02d", i))
		if err := copyPath(src, dest); err != nil {
			return nil, fmt.Errorf("copy mount %s: %w", m.Destination, err)
		}
		out = append(out, CopiedMount{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			CopyPath:    dest,
			ReadWrite:   m.RW,
		})
	}
	return out, nil
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlinks are not copied")
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, rel)
			entryInfo, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if entryInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink refused: %s", path)
			}
			if d.IsDir() {
				return os.MkdirAll(target, entryInfo.Mode().Perm())
			}
			if !entryInfo.Mode().IsRegular() {
				return fmt.Errorf("unsupported file type: %s", path)
			}
			return copyFile(path, target, entryInfo.Mode().Perm())
		})
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type: %s", src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return copyFile(src, dst, info.Mode().Perm())
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func replicaDir(parentName, replicaName string) string {
	return filepath.Join(replicaDataRoot, safePathName(parentName), "replicas", safePathName(replicaName))
}

func safePathName(name string) string {
	name = strings.TrimPrefix(name, "/")
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "container"
	}
	return b.String()
}

func snapshotImageName(parentName, replicaName string) string {
	return "serverpilot/replica-" + strings.ToLower(safePathName(parentName)) + "-" + strings.ToLower(safePathName(replicaName)) + ":" + strconv.FormatInt(time.Now().Unix(), 10)
}

func containerName(name string) string { return strings.TrimPrefix(name, "/") }

func countReplicas(reg *registry, parentID, parentName string) int {
	n := 0
	for _, r := range reg.Replicas {
		if r.ParentID == parentID || r.ParentName == parentName {
			n++
		}
	}
	return n
}

func replicaByName(reg *registry, name string) *Replica {
	idx := replicaIndexByName(reg, name)
	if idx < 0 {
		return nil
	}
	return &reg.Replicas[idx]
}

func replicaIndexByName(reg *registry, name string) int {
	for i := range reg.Replicas {
		if reg.Replicas[i].Name == name {
			return i
		}
	}
	return -1
}

func loadRegistry() *registry {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		return &registry{}
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return &registry{}
	}
	return &reg
}

func saveRegistry(reg *registry) error {
	if err := os.MkdirAll(registryDir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(registryDir, ".container-replicas-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, registryFile)
}

func switchNginxPort(oldPort, newPort int) ([]string, error) {
	if oldPort <= 0 || newPort <= 0 {
		return nil, nil
	}
	sites, err := nginx.ListSites()
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, site := range sites {
		if site.ProxyPass == "" || !proxyPassMatchesPort(site.ProxyPass, oldPort) {
			continue
		}
		name := filepath.Base(site.ConfigPath)
		content, err := os.ReadFile(site.ConfigPath)
		if err != nil {
			return changed, fmt.Errorf("read nginx config %s: %w", name, err)
		}
		updated := replaceProxyPort(string(content), oldPort, newPort)
		if updated == string(content) {
			continue
		}
		if err := atomicWrite(site.ConfigPath, []byte(updated), 0o644); err != nil {
			return changed, fmt.Errorf("write nginx config %s: %w", name, err)
		}
		changed = append(changed, name)
	}
	return changed, nil
}

func deleteNginxSitesByPort(port int, progress Progress) error {
	if port <= 0 {
		return nil
	}
	sites, err := nginx.ListSites()
	if err != nil {
		return fmt.Errorf("list nginx sites: %w", err)
	}
	var removed []string
	for _, site := range sites {
		if site.ProxyPass == "" || !proxyPassMatchesPort(site.ProxyPass, port) {
			continue
		}
		name := filepath.Base(site.ConfigPath)
		if progress != nil {
			display := site.Domain
			if display == "" {
				display = name
			}
			progress("Removing Nginx site " + display + "...")
		}
		if err := removeNginxSiteFiles(site); err != nil {
			return err
		}
		if site.Domain != "" && site.Domain != "_" {
			_ = deleteCertbotCert(site.Domain, progress)
		}
		removed = append(removed, name)
	}
	if len(removed) == 0 {
		return nil
	}
	if err := nginx.ReloadNginx(); err != nil {
		return fmt.Errorf("nginx reload after site deletion failed: %w", err)
	}
	return nil
}

func removeNginxSiteFiles(site nginx.Site) error {
	name := filepath.Base(site.ConfigPath)
	availablePath := filepath.Join("/etc/nginx/sites-available", name)
	if err := safeRemoveNginxFile("/etc/nginx/sites-available", availablePath, false); err != nil {
		return fmt.Errorf("remove nginx available site %s: %w", name, err)
	}
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", name)
	if err := safeRemoveNginxFile("/etc/nginx/sites-enabled", enabledPath, true); err != nil {
		return fmt.Errorf("remove nginx enabled site %s: %w", name, err)
	}
	return nil
}

func safeRemoveNginxFile(baseDir, path string, allowSymlink bool) error {
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(baseAbs, pathAbs)
	if err != nil {
		return err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return fmt.Errorf("path escapes nginx directory")
	}
	info, err := os.Lstat(pathAbs)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to remove directory")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !allowSymlink {
			return fmt.Errorf("refusing symlink in sites-available")
		}
		return os.Remove(pathAbs)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular file")
	}
	if allowSymlink {
		return fmt.Errorf("refusing non-symlink in sites-enabled")
	}
	return os.Remove(pathAbs)
}

func deleteCertbotCert(domain string, progress Progress) error {
	if !validCertName(domain) {
		return fmt.Errorf("invalid certificate name")
	}
	certPath := filepath.Join("/etc/letsencrypt/live", domain)
	if _, err := os.Stat(certPath); err != nil {
		return nil
	}
	certbotBin, err := deps.FindCertbot()
	if err != nil {
		if progress != nil {
			progress("WARNING: certbot not found; SSL certificate for " + domain + " was not deleted.")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, certbotBin, "delete", "--cert-name", domain, "--non-interactive").CombinedOutput(); err != nil {
		if progress != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			progress("WARNING: certbot delete failed for " + domain + ": " + msg)
		}
		return nil
	}
	if progress != nil {
		progress("Removed SSL certificate for " + domain + ".")
	}
	return nil
}

func validCertName(name string) bool {
	return certRegex.MatchString(name) && strings.Contains(name, ".")
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sp-replica-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func findDomainByPort(port int) string {
	if port <= 0 {
		return ""
	}
	sites, err := nginx.ListSites()
	if err != nil {
		return ""
	}
	for _, site := range sites {
		if proxyPassMatchesPort(site.ProxyPass, port) {
			return site.Domain
		}
	}
	return ""
}

func proxyPassMatchesPort(proxyPass string, port int) bool {
	if port <= 0 {
		return false
	}
	want := strconv.Itoa(port)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		prefix := "http://" + host + ":"
		if strings.HasPrefix(proxyPass, prefix) {
			rest := strings.TrimPrefix(proxyPass, prefix)
			end := 0
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			return end > 0 && rest[:end] == want
		}
	}
	return false
}

func replaceProxyPort(content string, oldPort, newPort int) string {
	oldStr := strconv.Itoa(oldPort)
	newStr := strconv.Itoa(newPort)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		content = strings.ReplaceAll(content, "http://"+host+":"+oldStr+";", "http://"+host+":"+newStr+";")
		content = strings.ReplaceAll(content, "http://"+host+":"+oldStr+"/", "http://"+host+":"+newStr+"/")
	}
	return content
}

func rewriteMountPaths(mounts []CopiedMount, oldName, newName string) []CopiedMount {
	out := append([]CopiedMount(nil), mounts...)
	for i := range out {
		out[i].CopyPath = strings.Replace(out[i].CopyPath, safePathName(oldName), safePathName(newName), 1)
	}
	return out
}

func StreamProgress(w io.Writer) Progress {
	return func(line string) {
		bw := bufio.NewWriter(w)
		_, _ = bw.WriteString(line + "\n")
		_ = bw.Flush()
	}
}
