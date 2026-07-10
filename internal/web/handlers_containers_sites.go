package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/docker"
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
	if strings.TrimSpace(req.ContainerID) == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "container_id required"})
		return
	}
	if err := composeContainerBlocked(req.ContainerID); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "compose containers use stack deploy for port changes"})
		return
	}
	if req.HostPort < 1 || req.HostPort > 65535 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid host port"})
		return
	}
	if err := docker.PublishPort(docker.PublishPortRequest{
		ContainerID:   req.ContainerID,
		HostPort:      req.HostPort,
		ContainerPort: req.ContainerPort,
		Protocol:      req.Protocol,
	}); err != nil {
		log.Printf("publish port failed: %v", err)
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "failed to publish port"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{
		"message": "port published",
		"port":    strconv.Itoa(req.HostPort),
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

func createSiteFromRequest(req siteCreateRequestV2) (sites.SiteRecord, error) {
	tmplType := templates.TemplateType(strings.ToLower(strings.TrimSpace(req.TemplateType)))
	if !templates.ValidTemplateType(tmplType) {
		return sites.SiteRecord{}, fmt.Errorf("invalid template type")
	}
	return sites.Create(sites.CreateRequest{
		ContainerID:         strings.TrimSpace(req.ContainerID),
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
