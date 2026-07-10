package web

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/mrthoabby/serverpilot/internal/compose"
	"github.com/mrthoabby/serverpilot/internal/deps"
)

type composeValidateRequest struct {
	Name        string `json:"name"`
	RootDir     string `json:"root_dir"`
	ComposeFile string `json:"compose_file"`
}

type composeDeployRequest struct {
	Name          string `json:"name"`
	Alias         string `json:"alias,omitempty"`
	RootDir       string `json:"root_dir"`
	ComposeFile   string `json:"compose_file"`
	AppImageRef   string `json:"app_image_ref,omitempty"`
	RegistryUser  string `json:"registry_user,omitempty"`
	RegistryToken string `json:"registry_token,omitempty"`
}

type composeCloneRequest struct {
	ParentName   string                          `json:"parent_name"`
	CloneName    string                          `json:"clone_name"`
	Alias        string                          `json:"alias,omitempty"`
	Mounts       map[string]compose.VolumePolicy `json:"mounts"`
	ShareConfirm bool                            `json:"share_confirm,omitempty"`
}

type composeNameRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleComposeProjectsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	_ = compose.RefreshOutdatedFlags()
	items, err := compose.ListProjects()
	if err != nil {
		log.Printf("compose list: %v", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "failed to list compose projects"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: items})
}

func (s *Server) handleComposeValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req composeValidateRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	res, err := compose.AnalyzeProjectStrict(req.Name, req.RootDir, req.ComposeFile)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "compose validation failed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Data: res})
}

func (s *Server) handleComposeDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req composeDeployRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamComposeOperation(w, "compose-deploy", func(progress compose.Progress) (interface{}, error) {
		return compose.Deploy(compose.DeployRequest{
			Name:          req.Name,
			Alias:         req.Alias,
			RootDir:       req.RootDir,
			ComposeFile:   req.ComposeFile,
			AppImageRef:   req.AppImageRef,
			RegistryUser:  req.RegistryUser,
			RegistryToken: req.RegistryToken,
		}, progress)
	})
}

func (s *Server) handleComposeClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req composeCloneRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamComposeOperation(w, "compose-clone", func(progress compose.Progress) (interface{}, error) {
		return compose.Clone(compose.CloneRequest{
			ParentName:   req.ParentName,
			CloneName:    req.CloneName,
			Alias:        req.Alias,
			Mounts:       req.Mounts,
			ShareConfirm: req.ShareConfirm,
		}, progress)
	})
}

func (s *Server) handleComposeSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req composeCloneRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	name := req.CloneName
	if name == "" {
		name = req.ParentName
	}
	s.streamComposeOperation(w, "compose-sync", func(progress compose.Progress) (interface{}, error) {
		return compose.SyncClone(name, compose.CloneRequest{
			Mounts:       req.Mounts,
			ShareConfirm: req.ShareConfirm,
		}, progress)
	})
}

func (s *Server) handleComposeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req composeNameRequest
	if err := jsonDecode(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid request body"})
		return
	}
	s.streamComposeOperation(w, "compose-delete", func(progress compose.Progress) (interface{}, error) {
		if err := compose.DeleteProjectStack(req.Name, progress); err != nil {
			return nil, err
		}
		return map[string]bool{"success": true}, nil
	})
}

func (s *Server) streamComposeOperation(w http.ResponseWriter, stage string, run func(compose.Progress) (interface{}, error)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "streaming not supported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sseWriteEvent(w, flusher, "stage", jsonString(map[string]string{"stage": stage}))
	sseWriteLog(w, flusher, "Starting compose operation...")
	if !deps.ComposeAvailable() {
		pkg := deps.ComposePluginPackageForDistro()
		if pkg == "" {
			sseWriteEvent(w, flusher, "done", jsonString(map[string]interface{}{
				"success": false,
				"error":   "docker compose is not available on this distribution",
			}))
			return
		}
		sseWriteEvent(w, flusher, "done", jsonString(map[string]interface{}{
			"success":            false,
			"error":              "docker compose is not installed",
			"dependency_missing": pkg,
		}))
		return
	}
	result, err := run(func(msg string) {
		sseWriteLog(w, flusher, msg)
	})
	if err != nil {
		sseWriteEvent(w, flusher, "done", jsonString(map[string]interface{}{
			"success": false,
			"error":   "compose operation failed",
		}))
		return
	}
	sseWriteEvent(w, flusher, "done", jsonString(map[string]interface{}{
		"success": true,
		"result":  result,
	}))
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
