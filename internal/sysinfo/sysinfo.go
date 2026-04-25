package sysinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	// Aggressive GC: collect when heap grows 30% (default 100%).
	// This keeps RSS low for a long-running daemon.
	debug.SetGCPercent(30)
	// Limit total memory to 64 MB soft target.
	debug.SetMemoryLimit(64 * 1024 * 1024)
}

// releaseMemory forces a GC cycle and returns pages to the OS.
// Call after expensive operations that allocate temporary buffers.
func releaseMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}

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
	Disk          []DiskInfo        `json:"disk"`
	DiskBreakdown []DiskBreakdownEntry `json:"disk_breakdown,omitempty"`
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

// DiskBreakdownEntry shows how much space a specific directory uses.
type DiskBreakdownEntry struct {
	Path   string  `json:"path"`
	Label  string  `json:"label"`
	SizeMB float64 `json:"size_mb"`
	SizeGB float64 `json:"size_gb"`
}

// DiskDetailEntry represents a child item inside a directory with its size and type.
type DiskDetailEntry struct {
	Path   string  `json:"path"`
	Name   string  `json:"name"`
	SizeMB float64 `json:"size_mb"`
	SizeGB float64 `json:"size_gb"`
	IsDir  bool    `json:"is_dir"`
	Type   string  `json:"type"` // "dir", "file", "image", "log", "archive", "other"
}

// DiskTopFile represents one of the largest files on disk.
type DiskTopFile struct {
	Path   string  `json:"path"`
	Name   string  `json:"name"`
	SizeMB float64 `json:"size_mb"`
	SizeGB float64 `json:"size_gb"`
	Type   string  `json:"type"`
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

	historyMu.Lock()
	defer historyMu.Unlock()

	for _, svc := range services {
		snap := MemorySnapshot{Timestamp: now, MemMB: svc.MemMB}
		history := serviceHistory[svc.Name]
		history = append(history, snap)

		// Keep only the last maxSnapshots entries — simple and O(1) amortized.
		if len(history) > maxSnapshots {
			// Shift in place to avoid allocating a new slice.
			copy(history, history[len(history)-maxSnapshots:])
			history = history[:maxSnapshots]
		}
		serviceHistory[svc.Name] = history
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

	// These shell out — run in parallel via goroutines to minimize latency.
	var wg sync.WaitGroup
	var disk []DiskInfo
	var containers []ContainerStat
	var services []ServiceInfo

	wg.Add(3)
	go func() { defer wg.Done(); disk = readDiskInfo() }()
	go func() { defer wg.Done(); containers = readDockerStats() }()
	go func() { defer wg.Done(); services = readServices() }()
	wg.Wait()

	info.Disk = disk
	info.Containers = containers
	info.Services = services

	// Attach memory history to each service.
	for i := range info.Services {
		info.Services[i].MemHistory = getServiceHistory(info.Services[i].Name)
	}

	// Release old cache before overwriting to allow GC to reclaim it.
	cached = nil
	cached = info
	cacheTime = time.Now()
	releaseMemory()
	return info, nil
}

// CollectDiskBreakdown runs the (slow) disk breakdown scan independently.
// It has its own cache so it doesn't slow down the main Collect() call.
var (
	diskBreakdownMu    sync.Mutex
	diskBreakdownCache []DiskBreakdownEntry
	diskBreakdownTime  time.Time
	diskBreakdownTTL   = 30 * time.Second // longer TTL — du is expensive
)

func CollectDiskBreakdown() []DiskBreakdownEntry {
	diskBreakdownMu.Lock()
	defer diskBreakdownMu.Unlock()

	if diskBreakdownCache != nil && time.Since(diskBreakdownTime) < diskBreakdownTTL {
		return diskBreakdownCache
	}

	diskBreakdownCache = readDiskBreakdown()
	diskBreakdownTime = time.Now()
	releaseMemory()
	return diskBreakdownCache
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
// Only parses the 5 fields we need — exits early once all are found.
func readMemInfo() *MemoryInfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	mem := &MemoryInfo{}
	needed := 5
	for _, line := range strings.Split(string(data), "\n") {
		if needed <= 0 {
			break // all fields found — stop scanning
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(parts[1], 10, 64)
		valMB := val / 1024 // kB -> MB
		switch parts[0] {
		case "MemTotal:":
			mem.TotalMB = valMB
			needed--
		case "MemFree:":
			mem.FreeMB = valMB
			needed--
		case "MemAvailable:":
			mem.AvailableMB = valMB
			needed--
		case "Buffers:":
			mem.BuffersMB = valMB
			needed--
		case "Cached:":
			mem.CachedMB = valMB
			needed--
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

// readDiskBreakdown runs du on key directories to show what occupies disk space.
// It uses a 10-second timeout to prevent hanging on very large directories.
func readDiskBreakdown() []DiskBreakdownEntry {
	dirs := []struct {
		path  string
		label string
	}{
		{"/var/lib/docker", "Docker (images, containers, volumes)"},
		{"/var/log", "System Logs"},
		{"/home", "Home Directories"},
		{"/tmp", "Temporary Files"},
		{"/var/lib/mysql", "MySQL Data"},
		{"/var/lib/postgresql", "PostgreSQL Data"},
		{"/opt", "Optional Software (/opt)"},
		{"/usr", "System Programs (/usr)"},
		{"/var/cache", "Package Cache"},
		{"/etc", "Configuration (/etc)"},
		{"/snap", "Snap Packages"},
		{"/var/www", "Web Files (/var/www)"},
	}

	var entries []DiskBreakdownEntry
	for _, d := range dirs {
		// Check if directory exists before running du.
		if _, err := os.Stat(d.path); os.IsNotExist(err) {
			continue
		}
		// Use du -smx (megabytes, summarize, don't cross filesystems) with 5s timeout.
		cmd := exec.Command("du", "-smx", d.path)
		// Use Output() (stdout only) — NOT CombinedOutput — because du
		// often prints permission-denied to stderr which would corrupt parsing.
		done := make(chan []byte, 1)
		go func() {
			out, _ := cmd.Output()
			done <- out
		}()
		var output []byte
		select {
		case output = <-done:
		case <-time.After(5 * time.Second):
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			continue
		}
		if len(output) == 0 {
			continue
		}
		line := strings.TrimSpace(string(output))
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		sizeMB, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || sizeMB < 1 {
			continue // skip tiny directories
		}
		entries = append(entries, DiskBreakdownEntry{
			Path:   d.path,
			Label:  d.label,
			SizeMB: sizeMB,
			SizeGB: float64(int(sizeMB/1024*100)) / 100, // 2 decimal places
		})
	}

	// Sort by size descending — O(n log n).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SizeMB > entries[j].SizeMB
	})

	return entries
}

// classifyFileType returns a type string based on file extension.
func classifyFileType(name string, isDir bool) string {
	if isDir {
		return "dir"
	}
	lower := strings.ToLower(name)
	// Images
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico", ".tiff"} {
		if strings.HasSuffix(lower, ext) {
			return "image"
		}
	}
	// Logs
	for _, ext := range []string{".log", ".log.1", ".log.gz"} {
		if strings.HasSuffix(lower, ext) {
			return "log"
		}
	}
	if strings.Contains(lower, ".log.") {
		return "log"
	}
	// Archives
	for _, ext := range []string{".tar", ".gz", ".zip", ".bz2", ".xz", ".7z", ".rar", ".tgz", ".tar.gz"} {
		if strings.HasSuffix(lower, ext) {
			return "archive"
		}
	}
	return "file"
}

// DiskDetailDir lists the immediate children of a directory with their sizes.
// Uses du with a 10-second timeout. Children are sorted by size descending.
func DiskDetailDir(dirPath string) ([]DiskDetailEntry, error) {
	// Validate the path is absolute and exists.
	if !strings.HasPrefix(dirPath, "/") {
		return nil, fmt.Errorf("path must be absolute")
	}
	clean := filepath.Clean(dirPath)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("path not found: %s", clean)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", clean)
	}

	// Read directory entries.
	dirEntries, err := os.ReadDir(clean)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}

	// Run du on each child in parallel (with concurrency limit).
	type result struct {
		entry DiskDetailEntry
		ok    bool
	}

	results := make([]result, len(dirEntries))
	sem := make(chan struct{}, 4) // max 4 concurrent du processes (lower = less RSS)
	var wg sync.WaitGroup

	for i, de := range dirEntries {
		wg.Add(1)
		go func(idx int, d os.DirEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			childPath := filepath.Join(clean, d.Name())
			cmd := exec.Command("du", "-smx", childPath)
			// Use Output() (stdout only) — stderr has permission errors that corrupt parsing.
			done := make(chan []byte, 1)
			go func() {
				out, _ := cmd.Output()
				done <- out
			}()

			var output []byte
			select {
			case output = <-done:
			case <-time.After(5 * time.Second):
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				return
			}

			line := strings.TrimSpace(string(output))
			parts := strings.Fields(line)
			if len(parts) < 1 {
				return
			}
			sizeMB, parseErr := strconv.ParseFloat(parts[0], 64)
			if parseErr != nil {
				return
			}

			results[idx] = result{
				entry: DiskDetailEntry{
					Path:   childPath,
					Name:   d.Name(),
					SizeMB: sizeMB,
					SizeGB: float64(int(sizeMB/1024*100)) / 100,
					IsDir:  d.IsDir(),
					Type:   classifyFileType(d.Name(), d.IsDir()),
				},
				ok: true,
			}
		}(i, de)
	}
	wg.Wait()

	// Collect valid results.
	var entries []DiskDetailEntry
	for _, r := range results {
		if r.ok {
			entries = append(entries, r.entry)
		}
	}

	// Sort descending by size — O(n log n).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SizeMB > entries[j].SizeMB
	})

	// Release temp buffers from du processes.
	releaseMemory()

	return entries, nil
}

// DiskTopFiles finds the N largest files under a given root path.
// Uses find + sort, limited by timeout.
func DiskTopFiles(root string, limit int) ([]DiskTopFile, error) {
	if !strings.HasPrefix(root, "/") {
		return nil, fmt.Errorf("path must be absolute")
	}
	clean := filepath.Clean(root)
	if _, err := os.Stat(clean); err != nil {
		return nil, fmt.Errorf("path not found: %s", clean)
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}

	// find <root> -type f -printf '%s %p\n' | sort -rn | head -N
	// %s = size in bytes, %p = path
	script := fmt.Sprintf(
		`find %s -xdev -type f -printf '%%s %%p\n' 2>/dev/null | sort -rn | head -%d`,
		clean, limit,
	)
	cmd := exec.Command("sh", "-c", script)

	done := make(chan []byte, 1)
	go func() {
		out, _ := cmd.Output()
		done <- out
	}()

	var output []byte
	select {
	case output = <-done:
	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("timed out scanning %s", clean)
	}

	var files []DiskTopFile
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		sizeBytes, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			continue
		}
		fpath := parts[1]
		sizeMB := sizeBytes / (1024 * 1024)
		name := filepath.Base(fpath)

		files = append(files, DiskTopFile{
			Path:   fpath,
			Name:   name,
			SizeMB: float64(int(sizeMB*100)) / 100,
			SizeGB: float64(int(sizeMB/1024*100)) / 100,
			Type:   classifyFileType(name, false),
		})
	}

	releaseMemory()
	return files, nil
}

// DeletePaths deletes the specified file/directory paths.
// Returns a map of path → error message (empty string on success).
// Only allows paths under safe root directories.
func DeletePaths(paths []string) map[string]string {
	results := make(map[string]string, len(paths))

	// Safety: never allow deleting these roots — O(1) lookup via map.
	blocked := map[string]bool{
		"/": true, "/bin": true, "/sbin": true, "/boot": true,
		"/dev": true, "/proc": true, "/sys": true, "/run": true,
		"/usr": true, "/usr/bin": true, "/usr/sbin": true, "/usr/lib": true,
		"/etc": true, "/etc/serverpilot": true, "/var": true, "/lib": true,
	}

	for _, p := range paths {
		clean := filepath.Clean(p)
		if !strings.HasPrefix(clean, "/") {
			results[p] = "path must be absolute"
			continue
		}

		if blocked[clean] {
			results[p] = "cannot delete protected system path"
			continue
		}

		// Verify the path exists.
		fi, err := os.Lstat(clean)
		if err != nil {
			results[p] = "not found"
			continue
		}

		if fi.IsDir() {
			err = os.RemoveAll(clean)
		} else {
			err = os.Remove(clean)
		}
		if err != nil {
			results[p] = err.Error()
		} else {
			results[p] = ""
		}
	}

	return results
}

// readDockerStats gets a snapshot of container resource usage.
// Uses --no-stream for a single non-blocking read.
func readDockerStats() []ContainerStat {
	cmd := exec.Command("/usr/bin/docker", "stats", "--no-stream",
		"--format", `{"name":"{{.Name}}","id":"{{.ID}}","cpu":"{{.CPUPerc}}","mem_usage":"{{.MemUsage}}","mem_perc":"{{.MemPerc}}","net_io":"{{.NetIO}}","block_io":"{{.BlockIO}}","pids":"{{.PIDs}}"}`)
	cmd.Stderr = io.Discard // don't buffer stderr
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
