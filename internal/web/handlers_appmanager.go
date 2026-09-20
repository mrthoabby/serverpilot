package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/appmanager"
	"nhooyr.io/websocket"
)

func (s *Server) appManagerReady(w http.ResponseWriter) bool {
	if s.appManager == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResponse{Error: "application manager is unavailable"})
		return false
	}
	return true
}

func writeAppManagerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, appmanager.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request"})
	case errors.Is(err, appmanager.ErrNotFound):
		writeJSON(w, http.StatusNotFound, apiResponse{Error: "resource not found"})
	case errors.Is(err, appmanager.ErrConflict):
		writeJSON(w, http.StatusConflict, apiResponse{Error: "request conflicts with current state"})
	default:
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "application manager operation failed"})
	}
}

func appManagerPage(r *http.Request) (int, int, error) {
	limit, offset := 100, 0
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return 0, 0, appmanager.ErrInvalid
		}
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 1_000_000 {
			return 0, 0, appmanager.ErrInvalid
		}
	}
	return limit, offset, nil
}

func (s *Server) handleAppManagerOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.Overview(r.Context())
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerGitHub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.GitHubConnection(r.Context())
	if errors.Is(err, appmanager.ErrNotFound) {
		writeJSON(w, http.StatusOK, apiResponse{Data: nil})
		return
	}
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerGitHubConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req appmanager.GitHubConnectionInput
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.ConfigureGitHub(r.Context(), req)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerGitHubSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	if err := s.appManager.SyncGitHubRepositories(r.Context()); err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: map[string]bool{"synchronized": true}})
}

func (s *Server) handleAppManagerRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListRepositories(r.Context(), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListApplications(r.Context(), r.URL.Query().Get("assignment"), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerApplicationDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.GetApplication(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerApplicationCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req appmanager.CreateApplicationInput
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.CreateApplication(r.Context(), req)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, apiResponse{Data: data})
}

func (s *Server) handleAppManagerWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	id := r.URL.Query().Get("application_id")
	data, err := s.appManager.GeneratedWorkflow(r.Context(), id)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: map[string]string{"workflow": data}})
}

func (s *Server) handleAppManagerProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListProjects(r.Context(), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerProjectCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req appmanager.CreateProjectInput
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.CreateProject(r.Context(), req)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, apiResponse{Data: data})
}

func (s *Server) handleAppManagerConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	ownerType, ownerID := r.URL.Query().Get("owner_type"), r.URL.Query().Get("owner_id")
	data, err := s.appManager.ListConfiguration(r.Context(), ownerType, ownerID)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerConfigurationSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.EnvironmentConfigurationSummary(r.Context(), r.URL.Query().Get("environment_id"))
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerConfigurationReplace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req struct {
		OwnerType string                          `json:"owner_type"`
		OwnerID   string                          `json:"owner_id"`
		Entries   []appmanager.ConfigurationInput `json:"entries"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if err := s.appManager.ReplaceConfiguration(r.Context(), req.OwnerType, req.OwnerID, req.Entries); err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: map[string]bool{"saved": true}})
}

func (s *Server) handleAppManagerReleases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListReleases(r.Context(), r.URL.Query().Get("repository_id"), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerReleaseDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.GetRelease(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerArtifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListApplicationArtifacts(r.Context(), r.URL.Query().Get("application_id"), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerArtifactsCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	if err := s.appManager.CheckWaitingArtifacts(r.Context(), 100); err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: map[string]bool{"checked": true}})
}

func (s *Server) handleAppManagerDeployments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	limit, offset, err := appManagerPage(r)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	data, err := s.appManager.ListDeployments(r.Context(), r.URL.Query().Get("environment_id"), limit, offset)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerDeploymentDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.GetDeployment(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req struct {
		EnvironmentID string `json:"environment_id"`
		ArtifactID    string `json:"artifact_id"`
		Trigger       string `json:"trigger"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	if req.Trigger == "" {
		req.Trigger = "manual"
	}
	data, err := s.appManager.Deploy(r.Context(), req.EnvironmentID, req.ArtifactID, req.Trigger, s.config.Username)
	if err != nil && data.ID == "" {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, apiResponse{Data: data})
}

func (s *Server) handleAppManagerRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req struct {
		EnvironmentID string `json:"environment_id"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.Rollback(r.Context(), req.EnvironmentID, s.config.Username)
	if err != nil && data.ID == "" {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, apiResponse{Data: data})
}

func (s *Server) handleAppManagerAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	data, err := s.appManager.ListAgents(r.Context())
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: data})
}

func (s *Server) handleAppManagerPairingToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.CreatePairingToken(r.Context(), req.Name)
	if err != nil {
		writeAppManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, apiResponse{Data: data})
}

func (s *Server) handleAppManagerGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.appManager == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		http.Error(w, "invalid webhook", http.StatusBadRequest)
		return
	}
	_, duplicate, err := s.appManager.HandleGitHubWebhook(r.Context(), r.Header.Get("X-Hub-Signature-256"), r.Header.Get("X-GitHub-Delivery"), r.Header.Get("X-GitHub-Event"), body)
	if err != nil {
		http.Error(w, "webhook rejected", http.StatusUnauthorized)
		return
	}
	if duplicate {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleAppManagerAgentPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if !s.appManagerReady(w) {
		return
	}
	var req struct {
		PairingToken string `json:"pairing_token"`
		Name         string `json:"name"`
		Version      string `json:"version"`
	}
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	data, err := s.appManager.PairAgent(r.Context(), req.PairingToken, req.Name, req.Version)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "pairing failed"})
		return
	}
	writeJSON(w, http.StatusCreated, apiResponse{Data: data})
}

type appManagerAgentMessage struct {
	Type          string `json:"type"`
	JobID         string `json:"job_id,omitempty"`
	Status        string `json:"status,omitempty"`
	ResultCode    string `json:"result_code,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
	ImageDigest   string `json:"image_digest,omitempty"`
}

func (s *Server) handleAppManagerAgentWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.appManager == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	agentID := r.Header.Get("X-SP-Agent-ID")
	version := r.Header.Get("X-SP-Agent-Version")
	if _, err := s.appManager.AuthenticateAgent(r.Context(), agentID, strings.TrimPrefix(auth, "Bearer ")); err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)
	ctx := r.Context()
	defer s.appManager.MarkAgentOffline(context.Background(), agentID)
	for {
		if err := s.appManager.AgentHeartbeat(ctx, agentID, version); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "agent rejected")
			return
		}
		job, ok, err := s.appManager.NextAgentJob(ctx, agentID)
		if err != nil {
			_ = conn.Close(websocket.StatusInternalError, "job unavailable")
			return
		}
		out := map[string]any{"type": "heartbeat", "at": time.Now().UTC()}
		if ok {
			out = map[string]any{"type": "job", "job": job}
		}
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = wsWriteJSON(writeCtx, conn, out)
		cancel()
		if err != nil {
			return
		}
		readCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		var msg appManagerAgentMessage
		err = wsReadJSON(readCtx, conn, &msg)
		cancel()
		if err != nil {
			return
		}
		if msg.Type == "result" && ok {
			if msg.JobID != job.ID {
				_ = conn.Close(websocket.StatusPolicyViolation, "job mismatch")
				return
			}
			result := appmanager.AgentDeployResult{
				ContainerName: msg.ContainerName,
				HostPort:      msg.HostPort,
				ImageDigest:   msg.ImageDigest,
			}
			if err := s.appManager.CompleteAgentJob(ctx, agentID, msg.JobID, msg.Status, msg.ResultCode, result); err != nil {
				_ = conn.Close(websocket.StatusPolicyViolation, "invalid result")
				return
			}
		} else if msg.Type != "heartbeat" {
			_ = conn.Close(websocket.StatusPolicyViolation, "invalid message")
			return
		}
	}
}

func wsWriteJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, raw)
}
func wsReadJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	kind, raw, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	if kind != websocket.MessageText {
		return errors.New("text message required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid trailing data")
	}
	return nil
}
