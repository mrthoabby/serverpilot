package portalloc

import "fmt"

// PortOwnerRequest describes one permanent port reservation.
type PortOwnerRequest struct {
	Owner string
}

// ReserveOwners reserves multiple owner-bound ports atomically. On failure, all
// newly created owners from this call are released.
func ReserveOwners(requests []PortOwnerRequest, minPort, maxPort int) (map[string]int, error) {
	if len(requests) == 0 {
		return map[string]int{}, nil
	}
	seen := make(map[string]struct{}, len(requests))
	for _, req := range requests {
		if req.Owner == "" || len(req.Owner) > 128 {
			return nil, fmt.Errorf("invalid reservation owner")
		}
		if _, ok := seen[req.Owner]; ok {
			return nil, fmt.Errorf("duplicate reservation owner")
		}
		seen[req.Owner] = struct{}{}
	}

	out := make(map[string]int, len(requests))
	var reserved []string
	defer func() {
		if len(out) == len(requests) {
			return
		}
		for _, owner := range reserved {
			_ = ReleaseOwner(owner)
		}
	}()

	for _, req := range requests {
		port, err := ReserveOwner(req.Owner, minPort, maxPort)
		if err != nil {
			return nil, err
		}
		out[req.Owner] = port
		reserved = append(reserved, req.Owner)
	}
	return out, nil
}

// ReleaseOwners releases multiple owners, ignoring individual failures.
func ReleaseOwners(owners []string) {
	for _, owner := range owners {
		_ = ReleaseOwner(owner)
	}
}

// ComposeOwner builds a stable owner id for compose endpoint reservations.
func ComposeOwner(project, generation, service, containerPort string) string {
	return "compose:" + project + ":" + generation + ":" + service + ":" + containerPort
}
