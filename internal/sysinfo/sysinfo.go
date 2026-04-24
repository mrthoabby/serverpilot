package sysinfo

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache to avoid hammering docker stats and systemctl on every request.
// The expensive operations (docker stats, systemctl) are cached for cacheTTL.
var (
	cacheMu   sync.Mutex
	cached    *SystemInfo
	cacheTime time.Time
	cacheTTL  = 5 * time.Second
)

// SystemInfo holds all system resource information.
type SystemInfo struct {
	Hostname    string          `json:"hostname"`
	Uptime      string          `json:"uptime"`
	GoVersion   string          `json:"go_version"`
	NumCPU      int             `json:"num_cpu"`
	LoadAvg     *LoadAverage    `json:"load_avg"`
	Memory      *MemoryInfo     `json:"memory"`
	Disk        []DiskInfo      `json:"disk"`
	Containers  []ContainerStat `json:"containers"`
	SelfProcess *ProcessInfo    `json:"self_process"`
	Services    []ServiceInfo   `json:"services"`
	Timestamp   int64           `json:"timestamp"`
}

// LoadAverage from /proc/loadavg.
type LoadAverage struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// MemoryInfo from /proc/meminfo.
type MemoryInfo struct {
	TotalMB     int64   `json:"total_mb"`
	UsedMB      int64   `json:"used_mb"`
	FreeMB      int64   `json:"free_mb"`
	AvailableMB int64   `json:"available_mb"`
	BuffersMB   int64   `json:"buffers_mb"`
	CachedMB    int64   `json:"cached_mb"`
	UsedPercent float64 `json:"used_percent"`
}

// DiskInfo from df.
type DiskInfo struct {
	Filesystem  string  `json:"filesystem"`
	SizeMB      int64   `json:"size_mb"`
	UsedMB      int64   `json:"used_mb"`
	AvailMB     int64   `json:"avail_mb"`
	UsedPercent float64 `json:"used_percent"`
	MountPoint  string  `json:"mount_point"`
}

// ContainerStat from docker stats.
type ContainerStat struct {
	Name     string  `json:"name"`
	ID       string  `json:"id"`
	CPUPerc  float64 `json:"cpu_perc"`
	MemUsage string  `json:"mem_usage"`
	MemPerc  float64 `json:"mem_perc"`
	MemMB    float64 `json:"mem_mb"`
	NetIO    string  `json:"net_io"`
	BlockIO  string  `json:"block_io"`
	PIDs     int     `json:"pids"`
}

// ProcessInfo for the ServerPilot process itself.
type ProcessInfo struct {
	PID        int     `json:"pid"`
	MemMB      float64 `json:"mem_mb"`
	NumThreads int     `json:"num_threads"`
}

// ServiceInfo for system services (Docker, Nginx, ServerPilot).
type ServiceInfo struct {
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Active     bool            `json:"active"`
	MemMB      float64         `json:"mem_mb"`
	MemHistory []MemorySnapshot `json:"mem_history,omitempty"`
}

// MemorySnapshot stores a point-in-time memory reading.
type MemorySnapshot struct {
	Timestamp int64   `json:"ts"`
	MemMB     float64 `json:"mem_mb"`
}

// Memory history: stores snapshots every 5 minutes for the last 1 hour.
// 1 hour / 5 min = 12 data points per service. Lightweight in-memory.
const (
	historyInterval = 5 * time.Minute
	historyWindow   = 1 * time.Hour
	maxSnapshots    = 12 // historyWindow / historyInterval
)

var (
	historyMu       sync.Mutex
	serviceHistory  = make(map[string][]MemorySnapshot) // name -> snapshots
	historyStarted  bool
)

// StartHistoryCollector starts a background goroutine that takes memory
// snapshots of services every historyInterval. Call once at server start.
func StartHistoryCollector() {
	historyMu.Lock()
	if historyStarted {
		historyMu.Unlock()
		return
	}
	historyStarted = true
	historyMu.Unlock()

	// Take an initial snapshot immediately.
	takeSnapshot()

	go func() {
		ticker := time.NewTicker(historyInterval)
		defer ticker.Stop()
		for range ticker.C {
			takeSnapshot()
		}
	}()
}

func takeSnapshot() {
	services := readServices()
	now := time.Now().Unix()
	cutoff := time.Now().Add(-historyWindow).Unix()

	historyMu.Lock()
	defer historyMu.Unlock()

	for _, svc := range services {
		snap := MemorySnapshot{Timestamp: now, MemMB: svc.MemMB}
		history := serviceHistory[svc.Name]
		history = append(history, snap)

		// Trim old snapshots beyond the window.
		trimmed := history[:0]
		for _, s := range history {
			if s.Timestamp >= cutoff {
				trimmed = append(trimmed, s)
			}
		}
		// Cap at maxSnapshots.
		if len(trimmed) > maxSnapshots {
			trimmed = trimmed[len(trimmed)-maxSnapshots:]
		}
		serviceHistory[svc.Name] = trimmed
	}
}

func getServiceHistory(name string) []MemorySnapshot {
	historyMu.Lock()
	defer historyMu.Unlock()
	h := serviceHistory[name]
	if h == nil {
		return nil
	}
	// Return a copy to avoid race.
	cp := make([]MemorySnapshot, len(h))
	copy(cp, h)
	return cp
}

// Collect gathers all system information. Uses a short-lived cache (5s)
// so rapid polling from the frontend doesn't spawn docker/systemctl on
// every request. /proc reads are instant; the cache mainly protects the
// heavier exec.Command calls (docker stats, systemctl).
func Collect() (*SystemInfo, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cached != nil && time.Since(cacheTime) < cacheTTL {
		return cached, nil
	}

	info := &SystemInfo{
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		Timestamp: time.Now().Unix(),
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// These read /proc — essentially free.
	info.Uptime = readUptime()
	info.LoadAvg = readLoadAvg()
	info.Memory = readMemInfo()
	info.SelfProcess = readSelfProcess()

	// These shell out — cached to avoid overhead.
	info.Disk = readDiskInfo()
	info.Containers = readDockerStats()
	info.Services = readServices()

	// Attach memory history to each service.
	for i := range info.Services {
		info.Services[i].MemHistory = getServiceHistory(info.Services[i].Name)
	}

	cached = info
	cacheTime = time.Now()
	return info, nil
}

// readUptime reads /proc/uptime and returns a human-readable string.
func readUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "unknown"
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "unknown"
	}
	d := int(seconds) / 86400
	h := (int(seconds) % 86400) / 3600
	m := (int(seconds) % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// readLoadAvg reads /proc/loadavg.
func readLoadAvg() *LoadAverage {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return &LoadAverage{Load1: l1, Load5: l5, Load15: l15}
}

// readMemInfo reads /proc/meminfo.
func readMemInfo() *MemoryInfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	mem := &MemoryInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(parts[1], 10, 64)
		valMB := val / 1024 // kB -> MB
		switch parts[0] {
		case "MemTotal:":
			mem.TotalMB = valMB
		case "MemFree:":
			mem.FreeMB = valMB
		case "MemAvailable:":
			mem.AvailableMB = valMB
		case "Buffers:":
			mem.BuffersMB = valMB
		case "Cached:":
			mem.CachedMB = valMB
		}
	}
	mem.UsedMB = mem.TotalMB - mem.AvailableMB
	if mem.TotalMB > 0 {
		mem.UsedPercent = float64(mem.UsedMB) / float64(mem.TotalMB) * 100
	}
	return mem
}

// readDiskInfo uses df to get disk usage for non-tmpfs mounts.
func readDiskInfo() []DiskInfo {
	cmd := exec.Command("/bin/df", "-BM", "--output=source,size,used,avail,pcent,target")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	var disks []DiskInfo
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		fs := fields[0]
		// Skip virtual filesystems.
		if strings.HasPrefix(fs, "tmpfs") || strings.HasPrefix(fs, "devtmpfs") ||
			strings.HasPrefix(fs, "udev") || strings.HasPrefix(fs, "overlay") ||
			fs == "none" || fs == "shm" {
			continue
		}
		sizeMB, _ := strconv.ParseInt(strings.TrimSuffix(fields[1], "M"), 10, 64)
		usedMB, _ := strconv.ParseInt(strings.TrimSuffix(fields[2], "M"), 10, 64)
		availMB, _ := strconv.ParseInt(strings.TrimSuffix(fields[3], "M"), 10, 64)
		pctStr := strings.TrimSuffix(fields[4], "%")
		pct, _ := strconv.ParseFloat(pctStr, 64)
		disks = append(disks, DiskInfo{
			Filesystem:  fs,
			SizeMB:      sizeMB,
			UsedMB:      usedMB,
			AvailMB:     availMB,
			UsedPercent: pct,
			MountPoint:  fields[5],
		})
	}
	return disks
}

// readDockerStats gets a snapshot of container resource usage.
// Uses --no-stream for a single non-blocking read.
func readDockerStats() []ContainerStat {
	cmd := exec.Command("/usr/bin/docker", "stats", "--no-stream",
		"--format", `{"name":"{{.Name}}","id":"{{.ID}}","cpu":"{{.CPUPerc}}","mem_usage":"{{.MemUsage}}","mem_perc":"{{.MemPerc}}","net_io":"{{.NetIO}}","block_io":"{{.BlockIO}}","pids":"{{.PIDs}}"}`)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var stats []ContainerStat
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		var raw struct {
			Name     string `json:"name"`
			ID       string `json:"id"`
			CPU      string `json:"cpu"`
			MemUsage string `json:"mem_usage"`
			MemPerc  string `json:"mem_perc"`
			NetIO    string `json:"net_io"`
			BlockIO  string `json:"block_io"`
			PIDs     string `json:"pids"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		cpuVal, _ := strconv.ParseFloat(strings.TrimSuffix(raw.CPU, "%"), 64)
		memPercVal, _ := strconv.ParseFloat(strings.TrimSuffix(raw.MemPerc, "%"), 64)
		pidsVal, _ := strconv.Atoi(raw.PIDs)

		memMB := parseMemToMB(raw.MemUsage)

		stats = append(stats, ContainerStat{
			Name:     raw.Name,
			ID:       raw.ID,
			CPUPerc:  cpuVal,
			MemUsage: raw.MemUsage,
			MemPerc:  memPercVal,
			MemMB:    memMB,
			NetIO:    raw.NetIO,
			BlockIO:  raw.BlockIO,
			PIDs:     pidsVal,
		})
	}
	return stats
}

// parseMemToMB extracts the used memory in MB from docker stats format "123.4MiB / 1.94GiB".
func parseMemToMB(usage string) float64 {
	parts := strings.Split(usage, "/")
	if len(parts) < 1 {
		return 0
	}
	used := strings.TrimSpace(parts[0])
	used = strings.ToUpper(used)

	if strings.HasSuffix(used, "GIB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(used, "GIB"), 64)
		return val * 1024
	}
	if strings.HasSuffix(used, "MIB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(used, "MIB"), 64)
		return val
	}
	if strings.HasSuffix(used, "KIB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(used, "KIB"), 64)
		return val / 1024
	}
	if strings.HasSuffix(used, "B") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(used, "B"), 64)
		return val / (1024 * 1024)
	}
	return 0
}

// readSelfProcess reads this process's memory from /proc/self/status.
func readSelfProcess() *ProcessInfo {
	info := &ProcessInfo{
		PID: os.Getpid(),
	}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return info
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "VmRSS:":
			val, _ := strconv.ParseFloat(fields[1], 64)
			info.MemMB = val / 1024 // kB -> MB
		case "Threads:":
			info.NumThreads, _ = strconv.Atoi(fields[1])
		}
	}
	return info
}

// readServices checks the status of key services.
func readServices() []ServiceInfo {
	serviceNames := []string{"serverpilot", "docker", "nginx"}
	var services []ServiceInfo

	for _, name := range serviceNames {
		svc := ServiceInfo{Name: name}

		// Check if active.
		cmd := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", name)
		svc.Active = cmd.Run() == nil
		if svc.Active {
			svc.Status = "running"
		} else {
			svc.Status = "stopped"
		}

		// Get memory usage from systemctl show.
		cmd = exec.Command("/usr/bin/systemctl", "show", name, "--property=MemoryCurrent", "--no-pager")
		out, err := cmd.Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "MemoryCurrent=") {
				val := strings.TrimPrefix(line, "MemoryCurrent=")
				if val != "[not set]" && val != "" {
					bytes, _ := strconv.ParseFloat(val, 64)
					svc.MemMB = bytes / (1024 * 1024)
				}
			}
		}

		services = append(services, svc)
	}

	return services
}
