package appmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const pairingTTL = 10 * time.Minute

type PairingToken struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AgentCredentials struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

type AgentJob struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Service) CreatePairingToken(ctx context.Context, name string) (PairingToken, error) {
	name = strings.TrimSpace(name)
	if validateDisplayName(name, 80) != nil {
		return PairingToken{}, fmt.Errorf("%w: invalid agent name", ErrInvalid)
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return PairingToken{}, fmt.Errorf("generate pairing token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	id, err := newID()
	if err != nil {
		return PairingToken{}, err
	}
	now := s.now()
	expires := now.Add(pairingTTL)
	_, err = s.store.db.ExecContext(ctx, `INSERT INTO pairing_tokens(id,token_hash,name,expires_at,created_at) VALUES(?,?,?,?,?)`, id, hash[:], name, expires, now)
	if err != nil {
		return PairingToken{}, fmt.Errorf("save pairing token: %w", err)
	}
	return PairingToken{Token: token, Name: name, ExpiresAt: expires}, nil
}

func (s *Service) PairAgent(ctx context.Context, pairingToken, name, version string) (AgentCredentials, error) {
	if pairingToken == "" || len(pairingToken) > 128 || validateDisplayName(name, 80) != nil || len(version) > 64 {
		return AgentCredentials{}, fmt.Errorf("%w: invalid pairing request", ErrInvalid)
	}
	hash := sha256.Sum256([]byte(pairingToken))
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentCredentials{}, fmt.Errorf("begin agent pairing: %w", err)
	}
	defer tx.Rollback()
	var tokenID, expectedName string
	var expires time.Time
	var used sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,name,expires_at,used_at FROM pairing_tokens WHERE token_hash=?`, hash[:]).Scan(&tokenID, &expectedName, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) || used.Valid || !s.now().Before(expires) || subtle.ConstantTimeCompare([]byte(expectedName), []byte(name)) != 1 {
		return AgentCredentials{}, fmt.Errorf("%w: pairing token is invalid or expired", ErrInvalid)
	}
	if err != nil {
		return AgentCredentials{}, fmt.Errorf("load pairing token: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return AgentCredentials{}, fmt.Errorf("generate agent credential: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := sha256.Sum256([]byte(token))
	agentID, err := newID()
	if err != nil {
		return AgentCredentials{}, err
	}
	now := s.now()
	_, err = tx.ExecContext(ctx, `INSERT INTO agents(id,name,token_hash,status,version,last_heartbeat_at,created_at,updated_at) VALUES(?,?,?,'online',?,?,?,?)`, agentID, name, tokenHash[:], version, now, now, now)
	if err != nil {
		return AgentCredentials{}, mapConstraintError(err, "agent name already exists")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE pairing_tokens SET used_at=? WHERE id=? AND used_at IS NULL`, now, tokenID); err != nil {
		return AgentCredentials{}, fmt.Errorf("consume pairing token: %w", err)
	}
	if err = insertAudit(ctx, tx, "agent", "agent.pair", "agent", agentID, ""); err != nil {
		return AgentCredentials{}, err
	}
	if err = tx.Commit(); err != nil {
		return AgentCredentials{}, fmt.Errorf("commit agent pairing: %w", err)
	}
	return AgentCredentials{AgentID: agentID, Token: token}, nil
}

func (s *Service) AuthenticateAgent(ctx context.Context, agentID, token string) (Agent, error) {
	if !validID(agentID) || token == "" || len(token) > 128 {
		return Agent{}, fmt.Errorf("%w: invalid agent credential", ErrInvalid)
	}
	var item Agent
	var expected []byte
	var heartbeat sql.NullTime
	err := s.store.db.QueryRowContext(ctx, `SELECT id,name,token_hash,status,version,last_heartbeat_at,created_at FROM agents WHERE id=?`, agentID).Scan(&item.ID, &item.Name, &expected, &item.Status, &item.Version, &heartbeat, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, fmt.Errorf("%w: agent", ErrNotFound)
	}
	if err != nil {
		return Agent{}, fmt.Errorf("load agent: %w", err)
	}
	actual := sha256.Sum256([]byte(token))
	if len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
		return Agent{}, fmt.Errorf("%w: invalid agent credential", ErrInvalid)
	}
	if heartbeat.Valid {
		item.LastHeartbeatAt = heartbeat.Time
	}
	return item, nil
}

func (s *Service) AgentHeartbeat(ctx context.Context, agentID, version string) error {
	if !validID(agentID) || len(version) > 64 {
		return fmt.Errorf("%w: invalid heartbeat", ErrInvalid)
	}
	res, err := s.store.db.ExecContext(ctx, `UPDATE agents SET status='online',version=?,last_heartbeat_at=?,updated_at=? WHERE id=?`, version, s.now(), s.now(), agentID)
	if err != nil {
		return fmt.Errorf("save heartbeat: %w", err)
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return fmt.Errorf("%w: agent", ErrNotFound)
	}
	return nil
}

func (s *Service) MarkAgentOffline(ctx context.Context, agentID string) {
	if !validID(agentID) {
		return
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `UPDATE agents SET status='offline',updated_at=? WHERE id=?`, s.now(), agentID)
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM agent_jobs WHERE agent_id=? AND status='running' LIMIT 100`, agentID)
	if err != nil {
		return
	}
	var deploymentIDs []string
	for rows.Next() {
		var payload string
		if rows.Scan(&payload) == nil {
			var body struct {
				DeploymentID string `json:"deployment_id"`
			}
			if json.Unmarshal([]byte(payload), &body) == nil && validID(body.DeploymentID) {
				deploymentIDs = append(deploymentIDs, body.DeploymentID)
			}
		}
	}
	_ = rows.Close()
	_, _ = tx.ExecContext(ctx, `UPDATE agent_jobs SET status='failed',result_code='agent_disconnected',updated_at=? WHERE agent_id=? AND status='running'`, s.now(), agentID)
	for _, deploymentID := range deploymentIDs {
		_, _ = tx.ExecContext(ctx, `UPDATE deployments SET status='failed',log_summary='agent_disconnected',finished_at=? WHERE id=? AND status='running'`, s.now(), deploymentID)
	}
	_ = tx.Commit()
}

func (s *Service) ListAgents(ctx context.Context) ([]Agent, error) {
	result := []Agent{{ID: "local", Name: "This server", Status: "local", CreatedAt: s.now()}}
	rows, err := s.store.db.QueryContext(ctx, `SELECT id,name,status,version,last_heartbeat_at,created_at FROM agents ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Agent
		var heartbeat sql.NullTime
		if err := rows.Scan(&item.ID, &item.Name, &item.Status, &item.Version, &heartbeat, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		if heartbeat.Valid {
			item.LastHeartbeatAt = heartbeat.Time
			if s.now().Sub(heartbeat.Time) > 90*time.Second {
				item.Status = "offline"
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) NextAgentJob(ctx context.Context, agentID string) (AgentJob, bool, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentJob{}, false, fmt.Errorf("begin agent job claim: %w", err)
	}
	defer tx.Rollback()
	var job AgentJob
	var payload string
	err = tx.QueryRowContext(ctx, `SELECT id,kind,payload FROM agent_jobs WHERE agent_id=? AND status='queued' ORDER BY created_at LIMIT 1`, agentID).Scan(&job.ID, &job.Kind, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentJob{}, false, nil
	}
	if err != nil {
		return AgentJob{}, false, fmt.Errorf("load agent job: %w", err)
	}
	if job.Kind != "deploy" && job.Kind != "rollback" && job.Kind != "site.disable" {
		return AgentJob{}, false, fmt.Errorf("invalid queued agent job")
	}
	if !json.Valid([]byte(payload)) {
		return AgentJob{}, false, fmt.Errorf("invalid queued agent payload")
	}
	job.Payload = json.RawMessage(payload)
	res, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET status='running',updated_at=? WHERE id=? AND status='queued'`, s.now(), job.ID)
	if err != nil {
		return AgentJob{}, false, fmt.Errorf("claim agent job: %w", err)
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return AgentJob{}, false, fmt.Errorf("%w: agent job changed", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return AgentJob{}, false, fmt.Errorf("commit agent job claim: %w", err)
	}
	if job.Kind == "deploy" {
		var envelope struct {
			DeploymentID string `json:"deployment_id"`
		}
		if err := json.Unmarshal(job.Payload, &envelope); err != nil || !validID(envelope.DeploymentID) {
			return AgentJob{}, false, fmt.Errorf("invalid queued deployment")
		}
		spec, err := s.prepareAgentDeploySpec(ctx, envelope.DeploymentID)
		if err != nil {
			_, _ = s.store.db.ExecContext(ctx, `UPDATE agent_jobs SET status='failed',result_code='job_prepare_failed',updated_at=? WHERE id=? AND status='running'`, s.now(), job.ID)
			_ = s.failDeployment(ctx, envelope.DeploymentID, "agent_job_prepare_failed")
			return AgentJob{}, false, err
		}
		job.Payload, err = json.Marshal(spec)
		if err != nil {
			return AgentJob{}, false, fmt.Errorf("encode agent deployment")
		}
	}
	return job, true, nil
}

func (s *Service) CompleteAgentJob(ctx context.Context, agentID, jobID, status, resultCode string, result AgentDeployResult) error {
	if !validID(agentID) || !validID(jobID) || (status != "success" && status != "failed") || len(resultCode) > 64 {
		return fmt.Errorf("%w: invalid agent job result", ErrInvalid)
	}
	if status == "success" && (!validManagedContainerName(result.ContainerName) || result.HostPort < 1 || result.HostPort > 65535 || !validImageDigest(result.ImageDigest)) {
		return fmt.Errorf("%w: invalid agent deployment result", ErrInvalid)
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var payload string
	res, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET status=?,result_code=?,updated_at=? WHERE id=? AND agent_id=? AND status='running'`, status, resultCode, s.now(), jobID, agentID)
	if err != nil {
		return fmt.Errorf("complete agent job: %w", err)
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		return fmt.Errorf("%w: agent job", ErrConflict)
	}
	if err := tx.QueryRowContext(ctx, `SELECT payload FROM agent_jobs WHERE id=?`, jobID).Scan(&payload); err != nil {
		return fmt.Errorf("load agent job payload: %w", err)
	}
	var body struct {
		DeploymentID string `json:"deployment_id"`
	}
	if json.Unmarshal([]byte(payload), &body) == nil && validID(body.DeploymentID) {
		if status == "success" {
			var expectedContainer, expectedDigest string
			err := tx.QueryRowContext(ctx, `SELECT e.container_name,ara.image_digest FROM deployments d JOIN application_environments e ON e.id=d.environment_id JOIN application_release_artifacts ara ON ara.id=d.artifact_id WHERE d.id=?`, body.DeploymentID).Scan(&expectedContainer, &expectedDigest)
			if err != nil || expectedDigest != result.ImageDigest || managedContainerBase(expectedContainer) != managedContainerBase(result.ContainerName) {
				return fmt.Errorf("%w: agent result does not match deployment", ErrInvalid)
			}
		}
		deploymentStatus := DeploymentSuccess
		if status == "failed" {
			deploymentStatus = DeploymentFailed
		}
		_, _ = tx.ExecContext(ctx, `UPDATE deployments SET status=?,container_name=?,image_digest=?,log_summary=?,finished_at=? WHERE id=?`, deploymentStatus, result.ContainerName, result.ImageDigest, resultCode, s.now(), body.DeploymentID)
		if status == "success" {
			_, _ = tx.ExecContext(ctx, `UPDATE application_environments SET container_name=?,host_port=?,current_artifact_id=(SELECT artifact_id FROM deployments WHERE id=?),status='healthy',last_deployment_at=?,updated_at=? WHERE id=(SELECT environment_id FROM deployments WHERE id=?)`, result.ContainerName, result.HostPort, body.DeploymentID, s.now(), s.now(), body.DeploymentID)
		}
	}
	return tx.Commit()
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && isLowerHex(value[7:])
}

func managedContainerBase(value string) string {
	value = strings.TrimSuffix(value, "__blue")
	return strings.TrimSuffix(value, "__green")
}
