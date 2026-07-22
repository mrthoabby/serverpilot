package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/compose"
	"github.com/mrthoabby/serverpilot/internal/docker"
	"github.com/mrthoabby/serverpilot/internal/portalloc"
	"github.com/mrthoabby/serverpilot/internal/replicas"
	"github.com/mrthoabby/serverpilot/internal/sites"
	"github.com/mrthoabby/serverpilot/internal/templates"
)

type siteCreateRequestV2 struct {
	Domain              string                    `json:"domain"`
	TemplateType        string                    `json:"template_type"`
	Port                int                       `json:"port"`
	ContainerID         string                    `json:"container_id"`
	ContainerName       string                    `json:"container_name"`
	ContainerPort       int                       `json:"container_port"`
	IncludeWWW          bool                      `json:"include_www"`
	ReplaceExisting     bool                      `json:"replace_existing"`
	AllowSharedHostPort bool                      `json:"allow_shared_host_port"`
	EnableSSL           bool                      `json:"enable_ssl"`
	Options             templates.TemplateOptions `json:"options"`
}

type portAnalysisRequest struct {
	ContainerID string `json:"container_id"`
}

type portPublishRequest struct {
	ContainerID   string `json:"container_id"`
	HostPort      int    `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
	PreviewToken  string `json:"preview_token"`
}

type portReserveRequest struct {
	ContainerID   string `json:"container_id"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type containerReleaseRequest struct {
	Container     string `json:"container"`
	Image         string `json:"image"`
	Strategy      string `json:"strategy,omitempty"`
	HealthURL     string `json:"health_url,omitempty"`
	HealthTimeout string `json:"health_timeout,omitempty"`
	Drain         string `json:"drain,omitempty"`
}

type redirectActivateRequest struct {
	ConfigName   string `json:"config_name"`
	Target       string `json:"target"`
	Code         int    `json:"code"`
	DelaySeconds int    `json:"delay_seconds"`
	Message      string `json:"message"`
}

type redirectDeactivateRequest struct {
	ConfigName    string `json:"config_name"`
	ForceOriginal bool   `json:"force_original"`
}

func composeContainerBlocked(containerID string) error {
	labels, err := docker.LabelsForContainer(containerID)
	if err != nil {
		return nil
	}
	if docker.IsComposeContainer(labels) {
		return fmt.Errorf("compose-managed containers must be updated via stack deploy")
	}
	return nil
}

func (s *Server) handleContainerPortAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	containerID := strings.TrimSpace(r.URL.Query().Get("container_id"))
	if containerID == "" && r.Method == http.MethodPost {
		var req portAnalysisRequest
		if err := jsonDecode(r, &req); err == nil {
			containerID = strings.TrimSpace(req.ContainerID)
		}
	}
	if containerID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_id required"})
		return
	}
	if err := composeContainerBlocked(containerID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "compose containers use stack deploy for port changes"})
		return
	}
	analysis, err := docker.AnalyzePortPublish(containerID)
	if err != nil {
		log.Printf("port analysis failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to analyze container ports"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: analysis})
}

func (s *Server) handleContainerPublishPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req portPublishRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	containerID := strings.TrimSpace(req.ContainerID)
	if containerID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_id required"})
		return
	}
	if err := composeContainerBlocked(containerID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "compose containers use stack deploy for port changes"})
		return
	}
	containerPort := strings.TrimSpace(req.ContainerPort)
	if containerPort == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_port required"})
		return
	}
	protocol := strings.TrimSpace(req.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}

	owner, err := docker.PortReservationOwner(containerID, containerPort, protocol)
	if err != nil {
		log.Printf("publish port owner failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to resolve container port owner"})
		return
	}

	hostPort := req.HostPort
	created := false
	if hostPort < 1 {
		result, reserveErr := portalloc.ReserveOwnerWithMeta(owner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
		if reserveErr != nil {
			log.Printf("publish port reserve failed: %v", reserveErr)
			writeJSON(w, http.StatusServiceUnavailable, apiResponse{Error: "failed to reserve host port"})
			return
		}
		hostPort = result.Port
		created = result.Created
	} else if hostPort > 65535 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid host port"})
		return
	} else if err := portalloc.AssignOwnerPort(owner, hostPort); err != nil {
		log.Printf("publish port assign failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to reserve host port"})
		return
	}

	if err := docker.PublishPort(docker.PublishPortRequest{
		ContainerID:   containerID,
		HostPort:      hostPort,
		ContainerPort: containerPort,
		Protocol:      protocol,
	}); err != nil {
		if created {
			_ = portalloc.ReleaseOwner(owner)
		}
		log.Printf("publish port failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to publish port"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"message": "port published",
		"port":    strconv.Itoa(hostPort),
	}})
}

func (s *Server) handleContainerReservePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req portReserveRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	containerID := strings.TrimSpace(req.ContainerID)
	if containerID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_id required"})
		return
	}
	containerPort := strings.TrimSpace(req.ContainerPort)
	if containerPort == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_port required"})
		return
	}
	protocol := strings.TrimSpace(req.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	if err := composeContainerBlocked(containerID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "compose containers use stack deploy for port changes"})
		return
	}

	owner, err := docker.PortReservationOwner(containerID, containerPort, protocol)
	if err != nil {
		log.Printf("reserve port owner failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to resolve container port owner"})
		return
	}
	result, err := portalloc.ReserveOwnerWithMeta(owner, portalloc.DefaultMinPort, portalloc.DefaultMaxPort)
	if err != nil {
		log.Printf("reserve port failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, apiResponse{Error: "failed to reserve host port"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]interface{}{
		"port":           result.Port,
		"container_port": containerPort,
		"protocol":       protocol,
	}})
}

func (s *Server) handleSiteRedirectActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req redirectActivateRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	configName := strings.TrimSpace(req.ConfigName)
	if !isValidConfigName(configName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config name"})
		return
	}
	targetBase, _, err := normalizeRedirectTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid redirect target"})
		return
	}
	if err := sites.ActivateRedirect(configName, sites.RedirectSpec{
		Target:       targetBase,
		Code:         req.Code,
		DelaySeconds: req.DelaySeconds,
		Message:      req.Message,
	}); err != nil {
		log.Printf("redirect activate failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to activate redirect"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "redirect activated"}})
}

func (s *Server) handleSiteRedirectDeactivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req redirectDeactivateRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	configName := strings.TrimSpace(req.ConfigName)
	if !isValidConfigName(configName) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid config name"})
		return
	}
	if err := sites.DeactivateRedirect(configName, req.ForceOriginal); err != nil {
		log.Printf("redirect deactivate failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"message": "redirect deactivated"}})
}

func (s *Server) handleContainerRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req containerReleaseRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	container := strings.TrimSpace(req.Container)
	if container == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container is required"})
		return
	}
	if compose.ParseStrategy(req.Strategy) != compose.StrategyBlueGreen {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "only blue-green strategy is supported for container release"})
		return
	}
	s.streamReplicaOperation(w, "container-release", "Container release", func(progress replicas.Progress) (interface{}, error) {
		err := docker.ReleaseBlueGreenProgress(docker.BlueGreenRequest{
			Container:     container,
			Image:         strings.TrimSpace(req.Image),
			HealthURL:     strings.TrimSpace(req.HealthURL),
			HealthTimeout: parseWebDuration(req.HealthTimeout, 60*time.Second),
			Drain:         parseWebDuration(req.Drain, 10*time.Second),
		}, progress)
		if err != nil {
			return nil, err
		}
		return map[string]bool{"success": true}, nil
	})
}

type containerDeleteRequest struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	RemoveImage   bool   `json:"remove_image"`
	AllowCompose  bool   `json:"allow_compose"`
}

func (s *Server) handleContainerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req containerDeleteRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	ref := strings.TrimSpace(req.ContainerID)
	if ref == "" {
		ref = strings.TrimSpace(req.ContainerName)
	}
	if err := docker.ValidateContainerRef(ref); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid container"})
		return
	}

	reps, err := replicas.List()
	if err == nil {
		for _, rep := range reps {
			if rep.Name == ref || strings.TrimSpace(req.ContainerName) == rep.Name {
				writeJSON(w, http.StatusBadRequest, apiResponse{Error: "managed replicas must be deleted from the replica delete action"})
				return
			}
		}
	}

	result, err := docker.DeleteContainer(docker.DeleteContainerOptions{
		IDOrName:     ref,
		RemoveImage:  req.RemoveImage,
		AllowCompose: req.AllowCompose,
	})
	if err != nil {
		log.Printf("container-delete: %v", err)
		msg := "failed to delete container"
		lower := strings.ToLower(err.Error())
		switch {
		case strings.Contains(lower, "compose containers"):
			msg = "compose containers must be removed with compose down"
		case strings.Contains(lower, "container not found"):
			msg = "container not found"
		}
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: msg})
		return
	}

	message := "container deleted"
	if result.ImageRemoved {
		message = "container and image deleted"
	} else if req.RemoveImage && result.ImageWarning != "" {
		message = "container deleted; image could not be removed (it may still be in use)"
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":        message,
			"container_id":   result.ContainerID,
			"container_name": result.ContainerName,
			"image_removed":  result.ImageRemoved,
			"image_id":       result.ImageID,
			"image_warning":  result.ImageWarning,
		},
	})
}

func createSiteFromRequest(req siteCreateRequestV2) (sites.SiteRecord, error) {
	tmplType := templates.TemplateType(strings.ToLower(strings.TrimSpace(req.TemplateType)))
	if !templates.ValidTemplateType(tmplType) {
		return sites.SiteRecord{}, fmt.Errorf("invalid template type")
	}
	containerID := strings.TrimSpace(req.ContainerID)
	if containerID != "" {
		if err := docker.ValidateSiteHostPort(containerID, req.Port, req.ContainerPort); err != nil {
			return sites.SiteRecord{}, err
		}
	}
	return sites.Create(sites.CreateRequest{
		ContainerID:         containerID,
		ContainerName:       strings.TrimSpace(req.ContainerName),
		HostPort:            req.Port,
		ContainerPort:       req.ContainerPort,
		Domain:              req.Domain,
		Template:            tmplType,
		Options:             req.Options,
		IncludeWWW:          req.IncludeWWW,
		AllowSharedHostPort: req.AllowSharedHostPort,
		ReplaceExisting:     req.ReplaceExisting,
	})
}

type siteSyncPortRequest struct {
	SiteID        string `json:"site_id"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ContainerPort string `json:"container_port"`
}

func (s *Server) handleSiteSyncPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req siteSyncPortRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	req.ContainerID = strings.TrimSpace(req.ContainerID)
	req.ContainerName = strings.TrimSpace(req.ContainerName)
	req.ContainerPort = strings.TrimSpace(req.ContainerPort)
	if req.ContainerPort == "" {
		req.ContainerPort = "3000"
	}
	if req.ContainerID == "" && req.ContainerName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_id or container_name is required"})
		return
	}

	hostPort, err := docker.SyncLinkedContainerSites(req.ContainerName, req.ContainerID, req.ContainerPort)
	if err != nil {
		log.Printf("site sync port: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to sync site port"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"host_port": hostPort,
			"message":   "nginx repointed to container port",
		},
	})
}

type siteUpdateMappingRequest struct {
	SiteID        string `json:"site_id"`
	ConfigName    string `json:"config_name"`
	Domain        string `json:"domain"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
}

func (s *Server) handleSiteUpdateMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req siteUpdateMappingRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.HostPort < 1 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "host_port is required"})
		return
	}
	if req.ContainerPort < 1 {
		req.ContainerPort = 3000
	}
	if req.SiteID == "" && strings.TrimSpace(req.ConfigName) == "" && strings.TrimSpace(req.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "site_id, config_name, or domain is required"})
		return
	}

	rec, err := docker.UpdateSiteMapping(docker.UpdateSiteMappingInput{
		SiteID:        strings.TrimSpace(req.SiteID),
		ConfigName:    strings.TrimSpace(req.ConfigName),
		Domain:        strings.TrimSpace(req.Domain),
		ContainerID:   strings.TrimSpace(req.ContainerID),
		ContainerName: strings.TrimSpace(req.ContainerName),
		HostPort:      req.HostPort,
		ContainerPort: req.ContainerPort,
	})
	if err != nil {
		log.Printf("site update mapping: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to update mapping"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"site_id":        rec.ID,
			"domain":         rec.Domain,
			"container_id":   rec.ContainerID,
			"container_name": rec.ContainerName,
			"host_port":      rec.HostPort,
			"container_port": rec.ContainerPort,
		},
	})
}
