package portalloc

import "fmt"

// PortOwnerRequest describes one permanent port reservation.
type PortOwnerRequest struct {
	Owner string
}

// ReserveOwners reserves multiple owner-bound ports atomically. On failure, only
// owners created during this call are released; reused reservations are kept.
func ReserveOwners(requests []PortOwnerRequest, minPort, maxPort int) (map[string]int, error) {
	ports, _, err := ReserveOwnersTracked(requests, minPort, maxPort)
	return ports, err
}

// ReserveOwnersTracked reserves multiple owners and returns which owners were
// newly created in this call (for transactional rollback).
func ReserveOwnersTracked(requests []PortOwnerRequest, minPort, maxPort int) (map[string]int, []string, error) {
	if len(requests) == 0 {
		return map[string]int{}, nil, nil
	}
	seen := make(map[string]struct{}, len(requests))
	for _, req := range requests {
		if req.Owner == "" || len(req.Owner) > 128 {
			return nil, nil, fmt.Errorf("invalid reservation owner")
		}
		if _, ok := seen[req.Owner]; ok {
			return nil, nil, fmt.Errorf("duplicate reservation owner")
		}
		seen[req.Owner] = struct{}{}
	}

	out := make(map[string]int, len(requests))
	var created []string
	defer func() {
		if len(out) == len(requests) {
			return
		}
		for _, owner := range created {
			_ = ReleaseOwner(owner)
		}
	}()

	for _, req := range requests {
		result, err := ReserveOwnerWithMeta(req.Owner, minPort, maxPort)
		if err != nil {
			return nil, nil, err
		}
		out[req.Owner] = result.Port
		if result.Created {
			created = append(created, req.Owner)
		}
	}
	return out, created, nil
}

// ReleaseOwners releases multiple owners, ignoring individual failures.
func ReleaseOwners(owners []string) {
	for _, owner := range owners {
		_ = ReleaseOwner(owner)
	}
}

// ComposeOwner builds a generation-scoped legacy owner id used before stable
// compose identities were introduced.
func ComposeOwner(project, generation, service, containerPort string) string {
	return "compose:" + project + ":" + generation + ":" + service + ":" + containerPort
}

// ComposeStableOwner builds the stable logical owner id for a compose endpoint.
func ComposeStableOwner(project, service, containerPort, protocol string) string {
	if protocol == "" {
		protocol = "tcp"
	}
	return "compose:" + project + ":" + service + ":" + containerPort + "/" + protocol
}

// DockerOwner builds a stable owner id for a standalone container endpoint.
func DockerOwner(containerName, containerPort, protocol string) string {
	if protocol == "" {
		protocol = "tcp"
	}
	return "docker:" + containerName + ":" + containerPort + "/" + protocol
}

// ComposeColorOwner builds a blue-green compose owner id scoped to a color slot.
func ComposeColorOwner(project, color, service, containerPort, protocol string) string {
	if protocol == "" {
		protocol = "tcp"
	}
	return "compose:" + project + ":" + color + ":" + service + ":" + containerPort + "/" + protocol
}

// DockerColorOwner builds a blue-green docker owner id scoped to a color slot.
func DockerColorOwner(containerName, color, containerPort, protocol string) string {
	if protocol == "" {
		protocol = "tcp"
	}
	return "docker:" + containerName + ":" + color + ":" + containerPort + "/" + protocol
}

// ReleaseColorOwners releases all owners for a compose project color prefix.
func ReleaseColorOwners(project, color string) {
	ReleaseOwnersByPrefix("compose:" + project + ":" + color + ":")
}
