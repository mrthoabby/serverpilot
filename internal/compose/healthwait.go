package compose

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const healthWaitBuffer = 30 * time.Second

type composeConfigServices struct {
	Services map[string]composeConfigService `json:"services"`
}

type composeConfigService struct {
	Healthcheck *composeConfigHealthcheck `json:"healthcheck"`
}

type composeConfigHealthcheck struct {
	StartPeriod string `json:"start_period"`
	Interval    string `json:"interval"`
	Retries     int    `json:"retries"`
}

// ServiceHealthWaitMin returns the minimum sensible health wait for a service
// based on its rendered compose healthcheck (start_period + interval*retries + buffer).
func (r *Runner) ServiceHealthWaitMin(service string) (time.Duration, bool, error) {
	raw, err := r.ConfigJSON()
	if err != nil {
		return 0, false, err
	}
	return ParseServiceHealthWaitMin(raw, service)
}

// ParseServiceHealthWaitMin parses compose config JSON from docker compose config --format json.
func ParseServiceHealthWaitMin(raw []byte, service string) (time.Duration, bool, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return 0, false, fmt.Errorf("service name is required")
	}
	var cfg composeConfigServices
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, false, fmt.Errorf("parse compose config: %w", err)
	}
	svc, ok := cfg.Services[service]
	if !ok || svc.Healthcheck == nil {
		return 0, false, nil
	}
	hc := svc.Healthcheck
	startPeriod, err := parseComposeDuration(hc.StartPeriod)
	if err != nil {
		return 0, false, err
	}
	interval, err := parseComposeDuration(hc.Interval)
	if err != nil {
		return 0, false, err
	}
	retries := hc.Retries
	if retries <= 0 {
		retries = 3
	}
	min := startPeriod + time.Duration(retries)*interval + healthWaitBuffer
	if min <= 0 {
		return 0, false, nil
	}
	return min, true, nil
}

func parseComposeDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid compose duration %q: %w", raw, err)
	}
	return d, nil
}

func effectiveHealthTimeout(runner Runner, service string, requested time.Duration) (time.Duration, string) {
	if requested <= 0 {
		requested = defaultHealthWait
	}
	min, ok, err := runner.ServiceHealthWaitMin(service)
	if err != nil || !ok || requested >= min {
		return requested, ""
	}
	return min, fmt.Sprintf("Extended health timeout from %s to %s (compose healthcheck start_period + retries)", requested, min)
}
