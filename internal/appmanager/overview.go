package appmanager

import (
	"context"
	"fmt"
)

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	var out Overview
	queries := []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(*) FROM projects`, &out.Projects},
		{`SELECT COUNT(*) FROM applications`, &out.Applications},
		{`SELECT COUNT(*) FROM applications WHERE project_id IS NULL`, &out.UnassignedApps},
		{`SELECT COUNT(*) FROM application_release_artifacts WHERE status='waiting_for_image'`, &out.WaitingArtifacts},
		{`SELECT COUNT(*) FROM deployments WHERE status='failed' AND created_at>=datetime('now','-7 days')`, &out.FailedDeployments},
		{`SELECT COUNT(*) FROM agents WHERE status='online' AND last_heartbeat_at>=datetime('now','-90 seconds')`, &out.ConnectedAgents},
	}
	for _, item := range queries {
		if err := s.store.db.QueryRowContext(ctx, item.query).Scan(item.dest); err != nil {
			return Overview{}, fmt.Errorf("load application manager overview: %w", err)
		}
	}
	out.ConnectedAgents++
	deployments, err := s.ListDeployments(ctx, "", 10, 0)
	if err != nil {
		return Overview{}, err
	}
	out.RecentDeployments = deployments
	return out, nil
}
