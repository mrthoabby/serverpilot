package docker

import (
	"context"
	"fmt"
	"math"
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
	Mode                PruneMode           `json:"mode"`
	Title               string              `json:"title"`
	Risk                string              `json:"risk"` // low, medium, high
	Description         string              `json:"description"`
	Removes             []string            `json:"removes"`
	Keeps               []string            `json:"keeps"`
	RequiresTypeConfirm bool                `json:"requires_type_confirm"`
	EstimateAvailable   bool                `json:"estimate_available"`
	EstimatedReclaimMB  float64             `json:"estimated_reclaim_mb,omitempty"`
	EstimatedReclaimGB  float64             `json:"estimated_reclaim_gb,omitempty"`
	EstimateParts       []PruneEstimatePart `json:"estimate_parts,omitempty"`
	EstimateNote        string              `json:"estimate_note,omitempty"`
}

// PruneEstimatePart is one line in the reclaim estimate breakdown.
type PruneEstimatePart struct {
	Label string  `json:"label"`
	GB    float64 `json:"gb"`
}

// ReclaimRow is one category from `docker system df` used for estimates.
type ReclaimRow struct {
	Type      string
	ReclaimMB float64
}

// ReclaimSnapshot indexes reclaimable space by docker system df category.
type ReclaimSnapshot struct {
	ImagesMB     float64
	ContainersMB float64
	VolumesMB    float64
	BuildCacheMB float64
}

// BuildReclaimSnapshot builds a snapshot from docker system df rows.
func BuildReclaimSnapshot(rows []ReclaimRow) ReclaimSnapshot {
	var snap ReclaimSnapshot
	for _, row := range rows {
		switch row.Type {
		case "Images":
			snap.ImagesMB = row.ReclaimMB
		case "Containers":
			snap.ContainersMB = row.ReclaimMB
		case "Local Volumes":
			snap.VolumesMB = row.ReclaimMB
		case "Build Cache":
			snap.BuildCacheMB = row.ReclaimMB
		}
	}
	return snap
}

// EstimatePruneReclaim estimates how much space a prune mode would free,
// using RECLAIMABLE columns from `docker system df` (same source Docker uses).
func (s ReclaimSnapshot) EstimatePruneReclaim(mode PruneMode) (totalMB float64, parts []PruneEstimatePart, note string) {
	add := func(label string, mb float64) {
		if mb <= 0 {
			return
		}
		totalMB += mb
		parts = append(parts, PruneEstimatePart{
			Label: label,
			GB:    math.Round(mb/1024*100) / 100,
		})
	}

	switch mode {
	case PruneSafe:
		// system prune (no -a): stopped containers, dangling images, networks, build cache.
		// Images RECLAIMABLE in `docker system df` is for prune -a; not included here.
		add("Contenedores parados", s.ContainersMB)
		add("Build cache", s.BuildCacheMB)
		note = "No incluye imágenes sin usar completas (usa «Todas las imágenes sin usar»). Puede liberar un poco más en imágenes dangling (<none>)."
	case PruneBuilder:
		add("Build cache", s.BuildCacheMB)
	case PruneImages:
		// system prune -a: all unused images + stopped containers + cache.
		add("Imágenes sin usar", s.ImagesMB)
		add("Contenedores parados", s.ContainersMB)
		add("Build cache", s.BuildCacheMB)
	case PruneVolumes:
		add("Volúmenes huérfanos", s.VolumesMB)
	case PruneAggressive:
		add("Imágenes sin usar", s.ImagesMB)
		add("Contenedores parados", s.ContainersMB)
		add("Volúmenes huérfanos", s.VolumesMB)
		add("Build cache", s.BuildCacheMB)
	}
	totalMB = math.Round(totalMB*100) / 100
	return totalMB, parts, note
}

// PruneModesWithEstimates returns prune metadata enriched with reclaim estimates.
func PruneModesWithEstimates(rows []ReclaimRow) []PruneModeInfo {
	modes := PruneModes()
	snap := BuildReclaimSnapshot(rows)
	hasData := len(rows) > 0
	for i := range modes {
		if !hasData {
			continue
		}
		mb, parts, note := snap.EstimatePruneReclaim(modes[i].Mode)
		modes[i].EstimateAvailable = true
		modes[i].EstimatedReclaimMB = mb
		modes[i].EstimatedReclaimGB = math.Round(mb/1024*100) / 100
		modes[i].EstimateParts = parts
		modes[i].EstimateNote = note
	}
	return modes
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
