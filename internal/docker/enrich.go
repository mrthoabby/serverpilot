package docker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

func enrichContainers(containers []Container) ([]Container, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return containers, nil
	}
	for i := range containers {
		labels, err := inspectLabels(dockerBin, containers[i].ID)
		if err == nil {
			containers[i].Compose = ParseComposeLabels(labels)
		}
		all, err := InspectAllPortMappings(containers[i].ID)
		if err == nil {
			var published, exposed []PortMapping
			for _, p := range all {
				if p.HostPort != "" {
					published = append(published, p)
				} else {
					exposed = append(exposed, p)
				}
			}
			containers[i].Ports = published
			containers[i].ExposedPorts = exposed
		}
	}
	return containers, nil
}

func inspectLabels(dockerBin, id string) (map[string]string, error) {
	cmd := exec.Command(dockerBin, "inspect", "--format", "{{json .Config.Labels}}", id)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect labels failed")
	}
	line := strings.TrimSpace(string(out))
	if line == "" || line == "null" {
		return map[string]string{}, nil
	}
	var labels map[string]string
	if err := json.Unmarshal([]byte(line), &labels); err != nil {
		return nil, err
	}
	return labels, nil
}

// LabelsForContainer returns Docker config labels for a container id or name.
func LabelsForContainer(id string) (map[string]string, error) {
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, err
	}
	return inspectLabels(dockerBin, id)
}
