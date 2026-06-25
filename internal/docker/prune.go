package docker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/mrthoabby/serverpilot/internal/deps"
)

// PruneMode selects a fixed, allowlisted docker prune command.
type PruneMode string

const (
	PruneSafe       PruneMode = "safe"
	PruneImages     PruneMode = "images"
	PruneVolumes    PruneMode = "volumes"
	PruneAggressive PruneMode = "aggressive"
	PruneBuilder    PruneMode = "builder"
)

const dockerPruneTimeout = 10 * time.Minute

// PruneModeInfo describes one prune option for the dashboard.
type PruneModeInfo struct {
	Mode                PruneMode `json:"mode"`
	Title               string    `json:"title"`
	Risk                string    `json:"risk"` // low, medium, high
	Description         string    `json:"description"`
	Removes             []string  `json:"removes"`
	Keeps               []string  `json:"keeps"`
	RequiresTypeConfirm bool      `json:"requires_type_confirm"`
}

// PruneResult is returned after a prune run.
type PruneResult struct {
	Mode   PruneMode `json:"mode"`
	Output string    `json:"output"`
}

// PruneModes returns metadata for every supported prune mode.
func PruneModes() []PruneModeInfo {
	return []PruneModeInfo{
		{
			Mode:        PruneSafe,
			Title:       "Limpieza básica (segura)",
			Risk:        "low",
			Description: "Elimina basura que Docker ya no usa. No toca contenedores ni imágenes en uso.",
			Removes: []string{
				"Contenedores parados (stopped)",
				"Imágenes dangling (<none>:<none>)",
				"Redes sin contenedores",
				"Build cache sin referencias",
			},
			Keeps: []string{
				"Contenedores corriendo",
				"Imágenes usadas por contenedores activos o parados",
				"Volúmenes con nombre",
			},
		},
		{
			Mode:        PruneBuilder,
			Title:       "Build cache",
			Risk:        "low",
			Description: "Solo borra la caché de builds de Docker. Los contenedores e imágenes no se tocan.",
			Removes:     []string{"Build cache de docker build / docker compose build"},
			Keeps: []string{
				"Contenedores, imágenes y volúmenes",
			},
		},
		{
			Mode:        PruneImages,
			Title:       "Todas las imágenes sin usar",
			Risk:        "medium",
			Description: "Borra imágenes que ningún contenedor (ni siquiera parado) referencia. Útil para liberar capas viejas.",
			Removes: []string{
				"Imágenes no referenciadas por ningún contenedor",
				"Más lo mismo que la limpieza básica",
			},
			Keeps: []string{
				"Imágenes de contenedores existentes (activos o parados)",
				"Volúmenes",
			},
			RequiresTypeConfirm: true,
		},
		{
			Mode:        PruneVolumes,
			Title:       "Volúmenes huérfanos",
			Risk:        "high",
			Description: "Borra volúmenes que ningún contenedor monta. Datos de apps desinstaladas pueden perderse.",
			Removes:     []string{"Volúmenes Docker no montados por ningún contenedor"},
			Keeps: []string{
				"Volúmenes en uso por contenedores activos o parados",
				"Imágenes y contenedores",
			},
			RequiresTypeConfirm: true,
		},
		{
			Mode:        PruneAggressive,
			Title:       "Limpieza agresiva (imágenes + volúmenes)",
			Risk:        "high",
			Description: "Combina imágenes sin usar y volúmenes huérfanos. Máximo espacio liberado; mayor riesgo de perder datos.",
			Removes: []string{
				"Todas las imágenes sin contenedor asociado",
				"Volúmenes huérfanos",
				"Contenedores parados, redes y cache",
			},
			Keeps: []string{
				"Contenedores corriendo y sus imágenes/volúmenes",
			},
			RequiresTypeConfirm: true,
		},
	}
}

func (m PruneMode) Valid() bool {
	switch m {
	case PruneSafe, PruneImages, PruneVolumes, PruneAggressive, PruneBuilder:
		return true
	default:
		return false
	}
}

func (m PruneMode) RequiresTypeConfirm() bool {
	switch m {
	case PruneImages, PruneVolumes, PruneAggressive:
		return true
	default:
		return false
	}
}

func (m PruneMode) dockerArgs() ([]string, error) {
	switch m {
	case PruneSafe:
		return []string{"system", "prune", "-f"}, nil
	case PruneImages:
		return []string{"system", "prune", "-a", "-f"}, nil
	case PruneVolumes:
		return []string{"volume", "prune", "-f"}, nil
	case PruneAggressive:
		return []string{"system", "prune", "-a", "--volumes", "-f"}, nil
	case PruneBuilder:
		return []string{"builder", "prune", "-f"}, nil
	default:
		return nil, fmt.Errorf("unsupported prune mode")
	}
}

// RunPrune executes one allowlisted docker prune command.
func RunPrune(mode PruneMode) (*PruneResult, error) {
	if !mode.Valid() {
		return nil, fmt.Errorf("invalid prune mode")
	}
	dockerBin, err := deps.DockerPath()
	if err != nil {
		return nil, fmt.Errorf("docker unavailable")
	}
	args, err := mode.dockerArgs()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerPruneTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerBin, args...)
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("docker prune timed out")
	}
	if runErr != nil {
		return nil, fmt.Errorf("docker prune failed")
	}

	return &PruneResult{
		Mode:   mode,
		Output: sanitizePruneOutput(string(out)),
	}, nil
}

func sanitizePruneOutput(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "Prune completed (no output)."
	}
	const maxLen = 2048
	if len(raw) > maxLen {
		return raw[:maxLen] + "…"
	}
	return raw
}
