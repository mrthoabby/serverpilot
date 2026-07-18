package sites

import "github.com/mrthoabby/serverpilot/internal/nginx"

// NginxActivationError is returned when a site config was written but nginx
// could not be activated. Report captures nginx -t output before rollback.
type NginxActivationError struct {
	Message string
	Report  nginx.RepairReport
	Cause   error
}

func (e *NginxActivationError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "failed to reload nginx"
}

func (e *NginxActivationError) Unwrap() error {
	return e.Cause
}
