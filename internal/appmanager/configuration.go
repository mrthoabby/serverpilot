package appmanager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

func (s *Service) ReplaceConfiguration(ctx context.Context, ownerType, ownerID string, entries []ConfigurationInput) error {
	if ownerType != "project" && ownerType != "environment" {
		return fmt.Errorf("%w: invalid configuration owner", ErrInvalid)
	}
	if !validID(ownerID) {
		return fmt.Errorf("%w: invalid configuration owner", ErrInvalid)
	}
	if err := ValidateConfigurationInputs(entries); err != nil {
		return err
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin configuration update: %w", err)
	}
	defer tx.Rollback()
	if err := s.replaceConfigurationTx(ctx, tx, ownerType, ownerID, entries); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, "system", "configuration.replace", ownerType, ownerID, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit configuration update: %w", err)
	}
	return nil
}

func (s *Service) replaceConfigurationTx(ctx context.Context, tx *sql.Tx, ownerType, ownerID string, entries []ConfigurationInput) error {
	if ownerType != "project" && ownerType != "environment" {
		return fmt.Errorf("%w: invalid configuration owner", ErrInvalid)
	}
	if err := ValidateConfigurationInputs(entries); err != nil {
		return err
	}
	table := "projects"
	if ownerType == "environment" {
		table = "application_environments"
	}
	var exists int
	query := `SELECT 1 FROM ` + table + ` WHERE id=?`
	if err := tx.QueryRowContext(ctx, query, ownerID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: configuration owner", ErrNotFound)
	} else if err != nil {
		return fmt.Errorf("load configuration owner: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configuration_entries WHERE owner_type=? AND owner_id=?`, ownerType, ownerID); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	now := s.now()
	for _, entry := range entries {
		id, err := newID()
		if err != nil {
			return err
		}
		ciphertext, err := s.vault.encrypt(entry.Value, "configuration:"+ownerType+":"+ownerID+":"+entry.Key)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO configuration_entries(id,owner_type,owner_id,key,value_cipher,secret,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id, ownerType, ownerID, entry.Key, ciphertext, entry.Secret, now, now); err != nil {
			return fmt.Errorf("save configuration: %w", err)
		}
	}
	return nil
}

func (s *Service) ListConfiguration(ctx context.Context, ownerType, ownerID string) ([]ConfigurationEntry, error) {
	if (ownerType != "project" && ownerType != "environment") || !validID(ownerID) {
		return nil, fmt.Errorf("%w: invalid configuration owner", ErrInvalid)
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT id,key,value_cipher,secret,updated_at FROM configuration_entries WHERE owner_type=? AND owner_id=? ORDER BY key`, ownerType, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list configuration: %w", err)
	}
	defer rows.Close()
	var result []ConfigurationEntry
	for rows.Next() {
		var item ConfigurationEntry
		var ciphertext string
		item.OwnerType, item.OwnerID = ownerType, ownerID
		if err := rows.Scan(&item.ID, &item.Key, &ciphertext, &item.Secret, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan configuration: %w", err)
		}
		item.HasValue = ciphertext != ""
		if !item.Secret && ciphertext != "" {
			value, err := s.vault.decrypt(ciphertext, "configuration:"+ownerType+":"+ownerID+":"+item.Key)
			if err != nil {
				return nil, err
			}
			item.Value = value
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ResolveEnvironmentVariables(ctx context.Context, environmentID string) ([]ResolvedVariable, error) {
	if !validID(environmentID) {
		return nil, fmt.Errorf("%w: invalid environment", ErrInvalid)
	}
	var projectID sql.NullString
	err := s.store.db.QueryRowContext(ctx, `SELECT a.project_id FROM application_environments e JOIN applications a ON a.id=e.application_id WHERE e.id=?`, environmentID).Scan(&projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: environment", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load environment project: %w", err)
	}
	var project []ResolvedVariable
	if projectID.Valid {
		project, err = s.resolveConfiguration(ctx, "project", projectID.String)
		if err != nil {
			return nil, err
		}
	}
	environment, err := s.resolveConfiguration(ctx, "environment", environmentID)
	if err != nil {
		return nil, err
	}
	return MergeVariables(project, environment), nil
}

func (s *Service) resolveConfiguration(ctx context.Context, ownerType, ownerID string) ([]ResolvedVariable, error) {
	rows, err := s.store.db.QueryContext(ctx, `SELECT key,value_cipher,secret FROM configuration_entries WHERE owner_type=? AND owner_id=?`, ownerType, ownerID)
	if err != nil {
		return nil, fmt.Errorf("resolve configuration: %w", err)
	}
	defer rows.Close()
	var result []ResolvedVariable
	for rows.Next() {
		var item ResolvedVariable
		var ciphertext string
		if err := rows.Scan(&item.Key, &ciphertext, &item.Secret); err != nil {
			return nil, fmt.Errorf("scan resolved configuration: %w", err)
		}
		item.Value, err = s.vault.decrypt(ciphertext, "configuration:"+ownerType+":"+ownerID+":"+item.Key)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func (s *Service) EnvironmentConfigurationSummary(ctx context.Context, environmentID string) (map[string]any, error) {
	if !validID(environmentID) {
		return nil, fmt.Errorf("%w: invalid environment", ErrInvalid)
	}
	var projectID sql.NullString
	var projectName string
	err := s.store.db.QueryRowContext(ctx, `SELECT a.project_id,COALESCE(p.name,'') FROM application_environments e JOIN applications a ON a.id=e.application_id LEFT JOIN projects p ON p.id=a.project_id WHERE e.id=?`, environmentID).Scan(&projectID, &projectName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: environment", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load environment configuration: %w", err)
	}
	projectEntries := []ConfigurationEntry{}
	if projectID.Valid {
		projectEntries, err = s.ListConfiguration(ctx, "project", projectID.String)
		if err != nil {
			return nil, err
		}
	}
	environmentEntries, err := s.ListConfiguration(ctx, "environment", environmentID)
	if err != nil {
		return nil, err
	}
	overrides := make(map[string]struct{}, len(environmentEntries))
	for _, entry := range environmentEntries {
		overrides[entry.Key] = struct{}{}
	}
	for i := range projectEntries {
		if _, ok := overrides[projectEntries[i].Key]; ok {
			projectEntries[i].Value = ""
		}
	}
	return map[string]any{"project_name": projectName, "project": projectEntries, "environment": environmentEntries, "updated_at": time.Now().UTC()}, nil
}
