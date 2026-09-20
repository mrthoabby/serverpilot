package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mrthoabby/serverpilot/internal/appmanager"
	"github.com/spf13/cobra"
	"nhooyr.io/websocket"
)

const agentConfigPath = "/etc/serverpilot/agent.json"

type agentConfig struct {
	ControllerURL string `json:"controller_url"`
	AgentID       string `json:"agent_id"`
	Token         string `json:"token"`
	Name          string `json:"name"`
}

var (
	agentController string
	agentPairToken  string
	agentName       string
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Pair and run a ServerPilot remote deployment agent",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("%q must be run as root", cmd.CommandPath())
		}
		return nil
	},
}

var agentPairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair this server with an Application Manager controller",
	RunE: func(cmd *cobra.Command, args []string) error {
		controller, err := validateAgentController(agentController)
		if err != nil {
			return err
		}
		if strings.TrimSpace(agentPairToken) == "" || len(agentPairToken) > 128 {
			return fmt.Errorf("invalid pairing token")
		}
		if strings.TrimSpace(agentName) == "" || len(agentName) > 80 {
			return fmt.Errorf("invalid agent name")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		credentials, err := pairRemoteAgent(ctx, controller, agentPairToken, agentName)
		if err != nil {
			return err
		}
		cfg := agentConfig{ControllerURL: controller.String(), AgentID: credentials.AgentID, Token: credentials.Token, Name: agentName}
		if err := saveAgentConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("Agent %q paired successfully.\n", agentName)
		return nil
	},
}

var agentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Run the paired deployment agent in the foreground",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAgentConfig()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAgent(ctx, cfg)
	},
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the local pairing state",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAgentConfig()
		if err != nil {
			return err
		}
		fmt.Printf("Agent: %s\nController: %s\nState: configured\n", cfg.Name, cfg.ControllerURL)
		return nil
	},
}

func init() {
	agentPairCmd.Flags().StringVar(&agentController, "controller", "", "HTTPS URL of the ServerPilot controller")
	agentPairCmd.Flags().StringVar(&agentPairToken, "token", "", "One-time pairing token")
	agentPairCmd.Flags().StringVar(&agentName, "name", "", "Agent display name")
	_ = agentPairCmd.MarkFlagRequired("controller")
	_ = agentPairCmd.MarkFlagRequired("token")
	_ = agentPairCmd.MarkFlagRequired("name")
	agentCmd.AddCommand(agentPairCmd, agentStartCmd, agentStatusCmd)
	rootCmd.AddCommand(agentCmd)
}

func validateAgentController(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("controller must be an HTTPS origin")
	}
	u.Path = ""
	return u, nil
}

func pairRemoteAgent(ctx context.Context, controller *url.URL, token, name string) (appmanager.AgentCredentials, error) {
	payload, err := json.Marshal(map[string]string{"pairing_token": token, "name": name, "version": version})
	if err != nil {
		return appmanager.AgentCredentials{}, fmt.Errorf("encode pairing request")
	}
	u := *controller
	u.Path = "/agent-api/v1/pair"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return appmanager.AgentCredentials{}, fmt.Errorf("create pairing request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return appmanager.AgentCredentials{}, fmt.Errorf("pairing request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		_, _ = io.CopyN(io.Discard, resp.Body, 8<<10)
		return appmanager.AgentCredentials{}, fmt.Errorf("controller rejected pairing")
	}
	var envelope struct {
		Data appmanager.AgentCredentials `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Data.AgentID == "" || envelope.Data.Token == "" {
		return appmanager.AgentCredentials{}, fmt.Errorf("invalid pairing response")
	}
	return envelope.Data, nil
}

func saveAgentConfig(cfg agentConfig) error {
	if _, err := validateAgentController(cfg.ControllerURL); err != nil || cfg.AgentID == "" || cfg.Token == "" {
		return fmt.Errorf("invalid agent configuration")
	}
	dir := filepath.Dir(agentConfigPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create agent configuration directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure agent configuration directory")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode agent configuration")
	}
	tmp, err := os.CreateTemp(dir, ".agent.json.*")
	if err != nil {
		return fmt.Errorf("create agent configuration")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure agent configuration")
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write agent configuration")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync agent configuration")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close agent configuration")
	}
	if err := os.Rename(tmpPath, agentConfigPath); err != nil {
		return fmt.Errorf("install agent configuration")
	}
	return nil
}

func loadAgentConfig() (agentConfig, error) {
	info, err := os.Lstat(agentConfigPath)
	if err != nil {
		return agentConfig{}, fmt.Errorf("agent is not paired")
	}
	if !info.Mode().IsRegular() || info.Mode()&0o077 != 0 {
		return agentConfig{}, fmt.Errorf("agent configuration has unsafe permissions")
	}
	f, err := os.OpenFile(agentConfigPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return agentConfig{}, fmt.Errorf("open agent configuration")
	}
	defer f.Close()
	var cfg agentConfig
	decoder := json.NewDecoder(io.LimitReader(f, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return agentConfig{}, fmt.Errorf("invalid agent configuration")
	}
	if _, err := validateAgentController(cfg.ControllerURL); err != nil || cfg.AgentID == "" || cfg.Token == "" || cfg.Name == "" {
		return agentConfig{}, fmt.Errorf("invalid agent configuration")
	}
	return cfg, nil
}

func runAgent(ctx context.Context, cfg agentConfig) error {
	backoff := time.Second
	for {
		err := runAgentSession(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			backoff = time.Second
		}
		delay := backoff + secureJitter(500*time.Millisecond)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func runAgentSession(ctx context.Context, cfg agentConfig) error {
	controller, err := validateAgentController(cfg.ControllerURL)
	if err != nil {
		return err
	}
	controller.Scheme = "wss"
	controller.Path = "/agent-api/v1/ws"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+cfg.Token)
	headers.Set("X-SP-Agent-ID", cfg.AgentID)
	headers.Set("X-SP-Agent-Version", version)
	conn, _, err := websocket.Dial(ctx, controller.String(), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		return fmt.Errorf("connect to controller")
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	for {
		kind, raw, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageText {
			return fmt.Errorf("unexpected controller message")
		}
		var message struct {
			Type string              `json:"type"`
			Job  appmanager.AgentJob `json:"job"`
		}
		if err := json.Unmarshal(raw, &message); err != nil {
			return fmt.Errorf("invalid controller message")
		}
		response := map[string]any{"type": "heartbeat"}
		if message.Type == "job" {
			if message.Job.Kind != "deploy" || message.Job.ID == "" {
				return fmt.Errorf("unsupported controller job")
			}
			var spec appmanager.AgentDeploySpec
			decoder := json.NewDecoder(bytes.NewReader(message.Job.Payload))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&spec); err != nil {
				return fmt.Errorf("invalid deployment job")
			}
			result, deployErr := appmanager.ExecuteAgentDeploy(ctx, spec)
			status, resultCode := "success", "deployed"
			if deployErr != nil {
				status, resultCode = "failed", "deploy_failed"
			}
			response = map[string]any{
				"type":           "result",
				"job_id":         message.Job.ID,
				"status":         status,
				"result_code":    resultCode,
				"container_name": result.ContainerName,
				"host_port":      result.HostPort,
				"image_digest":   result.ImageDigest,
			}
		} else if message.Type != "heartbeat" {
			return fmt.Errorf("unsupported controller message")
		}
		rawResponse, err := json.Marshal(response)
		if err != nil {
			return err
		}
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = conn.Write(writeCtx, websocket.MessageText, rawResponse)
		cancel()
		if err != nil {
			return err
		}
	}
}

func secureJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(max))
}
