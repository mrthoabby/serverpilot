package sysinfo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
	Hostname      string               `json:"hostname"`
	Uptime        string               `json:"uptime"`
	GoVersion     string               `json:"go_version"`
	NumCPU        int                  `json:"num_cpu"`
	LoadAvg       *LoadAverage         `json:"load_avg"`
	Memory        *MemoryInfo          `json:"memory"`
	Disk          []DiskInfo           `json:"disk"`
	DiskBreakdown []DiskBreakdownEntry `json:"disk_breakdown,omitempty"`
	DockerDisk    []DockerDiskStat     `json:"docker_disk,omitempty"`
	Containers    []ContainerStat      `json:"containers"`
	SelfProcess   *ProcessInfo         `json:"self_process"`
	Services      []ServiceInfo        `json:"services"`
	Timestamp     int64                `json:"timestamp"`
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
	Path    string  `json:"path"`
	Label   string  `json:"label"`
	SizeMB  float64 `json:"size_mb"`
	SizeGB  float64 `json:"size_gb"`
	Partial bool    `json:"partial,omitempty"` // true when du timed out or had errors
}

// DockerDiskStat holds one row from `docker system df`.
type DockerDiskStat struct {
	Type      string  `json:"type"`
	Total     int     `json:"total"`
	Active    int     `json:"active"`
	SizeMB    float64 `json:"size_mb"`
	ReclaimMB float64 `json:"reclaim_mb"`
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
			// Periodic forced memory release every 5 minutes.
			// This ensures accumulated garbage from exec.Command buffers,
			// JSON parsing, and /proc reads is returned to the OS even if
			// the GC hasn't hit the 30% threshold naturally.
			releaseMemory()
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
	var dockerDisk []DockerDiskStat

	wg.Add(4)
	go func() { defer wg.Done(); disk = readDiskInfo() }()
	go func() { defer wg.Done(); containers = readDockerStats() }()
	go func() { defer wg.Done(); services = readServices() }()
	go func() { defer wg.Done(); dockerDisk = readDockerDiskInfo() }()
	wg.Wait()

	info.Disk = disk
	info.Containers = containers
	info.Services = services
	info.DockerDisk = dockerDisk

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
// Uses a scanner to avoid loading the full file into memory.
// Only parses the 5 fields we need — exits early once all are found.
func readMemInfo() *MemoryInfo {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	mem := &MemoryInfo{}
	needed := 5

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if needed <= 0 {
			break
		}
		line := scanner.Text()
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

// parseDockerSizeMB converts Docker size strings like "3.5GB", "232kB", "0B" to MB.
// Docker uses decimal prefixes (1 GB = 1000 MB) in its output.
func parseDockerSizeMB(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "0B" {
		return 0
	}
	type unit struct {
		suffix string
		factor float64
	}
	// Docker uses decimal (SI) prefixes in `docker system df` output.
	units := []unit{
		{"TB", 1e6},
		{"GB", 1e3},
		{"MB", 1},
		{"kB", 1e-3},
		{"B", 1e-6},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			if err != nil {
				return 0
			}
			return v * u.factor
		}
	}
	return 0
}

// readDockerDiskInfo runs `docker system df` to get accurate per-category disk usage.
// This is the ONLY reliable way to measure Docker disk usage — `du /var/lib/docker`
// overcounts because overlay2 merged/ directories are counted multiple times.
func readDockerDiskInfo() []DockerDiskStat {
	// Use tab-separated format so multi-word types ("Local Volumes") parse cleanly.
	cmd := exec.Command("/usr/bin/docker", "system", "df",
		"--format", "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}\t{{.Total}}\t{{.Active}}")
	cmd.Stderr = io.Discard
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var stats []DockerDiskStat
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		typeName := parts[0]
		sizeMB := parseDockerSizeMB(parts[1])
		// Reclaimable format: "1.2GB (34%)" — extract size before the space.
		reclaimStr := parts[2]
		if idx := strings.Index(reclaimStr, " "); idx > 0 {
			reclaimStr = reclaimStr[:idx]
		}
		reclaimMB := parseDockerSizeMB(reclaimStr)
		total, _ := strconv.Atoi(parts[3])
		active, _ := strconv.Atoi(parts[4])

		stats = append(stats, DockerDiskStat{
			Type:      typeName,
			Total:     total,
			Active:    active,
			SizeMB:    math.Round(sizeMB*100) / 100,
			ReclaimMB: math.Round(reclaimMB*100) / 100,
		})
	}
	return stats
}

// readDiskBreakdown runs du on key directories to show what occupies disk space.
// Uses du -smx (-x = same filesystem only) to avoid traversing Docker overlay
// mount points, which would cause massive overcounting of Docker layer data.
// Timeout is 30s per directory (large dirs like /usr can be slow).
func readDiskBreakdown() []DiskBreakdownEntry {
	// /var/lib/docker is intentionally EXCLUDED from this list.
	// du on that path traverses overlay2 merged/ mount points and triple-counts
	// image layers. Docker disk usage is measured separately via readDockerDiskInfo().
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
		{"/root", "Root Home (/root)"},
		{"/srv", "Server Data (/srv)"},
		{"/var/lib", "Variable Data (/var/lib)"},
		{"/var/spool", "Mail/Print Spool (/var/spool)"},
		{"/var/backups", "Backups (/var/backups)"},
	}

	type duResult struct {
		idx     int
		sizeMB  float64
		partial bool // true when du timed out
	}

	// Run all du commands in parallel with concurrency limit.
	resultsCh := make(chan duResult, len(dirs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup

	validDirs := []struct {
		idx   int
		path  string
		label string
	}{}
	for i, d := range dirs {
		if _, err := os.Stat(d.path); os.IsNotExist(err) {
			continue
		}
		validDirs = append(validDirs, struct {
			idx   int
			path  string
			label string
		}{i, d.path, d.label})
	}

	for _, vd := range validDirs {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// -s: summarize, -m: megabytes, -x: same filesystem only.
			// The -x flag is critical: it prevents du from entering Docker overlay2
			// merged/ directories (which are overlay mount points on a different fs
			// type), avoiding the 3-4x overcounting that happens without it.
			cmd := exec.Command("du", "-smx", path)
			done := make(chan []byte, 1)
			go func() {
				out, _ := cmd.Output()
				done <- out
			}()

			var output []byte
			var timedOut bool
			select {
			case output = <-done:
			case <-time.After(30 * time.Second): // increased from 10s — /usr can be large
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				// Drain goroutine so it can exit and be GC'd.
				go func() { <-done }()
				timedOut = true
			}

			if timedOut {
				// Record a partial entry so it shows in the UI with a warning
				// instead of silently inflating "Other / System".
				resultsCh <- duResult{idx: idx, sizeMB: 0, partial: true}
				return
			}
			if len(output) == 0 {
				return
			}
			line := strings.TrimSpace(string(output))
			parts := strings.Fields(line)
			if len(parts) < 1 {
				return
			}
			sizeMB, err := strconv.ParseFloat(parts[0], 64)
			if err != nil {
				return
			}
			resultsCh <- duResult{idx: idx, sizeMB: sizeMB}
		}(vd.idx, vd.path)
	}

	wg.Wait()
	close(resultsCh)

	// Collect results, dedup overlapping paths (/var/lib vs /var/lib/docker).
	type idxResult struct {
		sizeMB  float64
		partial bool
	}
	resultByIdx := make(map[int]idxResult)
	for r := range resultsCh {
		resultByIdx[r.idx] = idxResult{sizeMB: r.sizeMB, partial: r.partial}
	}

	// Subtract child sizes from parent to avoid double-counting.
	// /var/lib includes /var/lib/docker (with -x, this is the actual layer data),
	// /var/lib/mysql, and /var/lib/postgresql.
	varLibIdx := -1
	dockerIdx := -1
	mysqlIdx := -1
	pgIdx := -1
	for i, d := range dirs {
		switch d.path {
		case "/var/lib":
			varLibIdx = i
		case "/var/lib/docker":
			dockerIdx = i
		case "/var/lib/mysql":
			mysqlIdx = i
		case "/var/lib/postgresql":
			pgIdx = i
		}
	}
	if varLibIdx >= 0 {
		if parent, ok := resultByIdx[varLibIdx]; ok {
			parentSize := parent.sizeMB
			for _, childIdx := range []int{dockerIdx, mysqlIdx, pgIdx} {
				if childIdx >= 0 {
					if child, ok := resultByIdx[childIdx]; ok {
						parentSize -= child.sizeMB
					}
				}
			}
			if parentSize < 0 {
				parentSize = 0
			}
			resultByIdx[varLibIdx] = idxResult{sizeMB: parentSize, partial: parent.partial}
		}
	}

	var entries []DiskBreakdownEntry
	for idx, res := range resultByIdx {
		// Show partial entries (timed-out) even with 0 MB so the UI can warn the user.
		if res.sizeMB < 1 && !res.partial {
			continue
		}
		sizeMB := res.sizeMB
		entries = append(entries, DiskBreakdownEntry{
			Path:    dirs[idx].path,
			Label:   dirs[idx].label,
			SizeMB:  sizeMB,
			SizeGB:  math.Round(sizeMB/1024*100) / 100, // fixed: was truncating with int()
			Partial: res.partial,
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
			// -x: stay on the same filesystem — avoids traversing Docker overlays.
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
				go func() { <-done }() // drain so goroutine can exit
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
					SizeGB: math.Round(sizeMB/1024*100) / 100,
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

	// Use a buffered channel so the goroutine can always send and exit,
	// even if we already returned due to timeout (prevents goroutine leak).
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
		// Drain the goroutine's send so it can exit and be GC'd.
		go func() { <-done }()
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
			SizeMB: math.Round(sizeMB*100) / 100,
			SizeGB: math.Round(sizeMB/1024*100) / 100,
			Type:   classifyFileType(name, false),
		})
	}

	releaseMemory()
	return files, nil
}

// ProcessMemInfo holds memory usage for a single system process.
type ProcessMemInfo struct {
	PID   int     `json:"pid"`
	Name  string  `json:"name"`
	RssMB float64 `json:"rss_mb"`
	State string  `json:"state"`
}

// MemoryDetail breaks down where RAM is actually going.
type MemoryDetail struct {
	TopProcesses []ProcessMemInfo `json:"top_processes"`
	CachedMB     int64            `json:"cached_mb"`
	BuffersMB    int64            `json:"buffers_mb"`
}

var (
	memDetailMu    sync.Mutex
	memDetailCache *MemoryDetail
	memDetailTime  time.Time
	memDetailTTL   = 5 * time.Second
)

// CollectMemoryDetail returns cache/buffers sizes and the top 25 processes by RSS.
// Reads /proc directly — no shell commands.
func CollectMemoryDetail() *MemoryDetail {
	memDetailMu.Lock()
	defer memDetailMu.Unlock()

	if memDetailCache != nil && time.Since(memDetailTime) < memDetailTTL {
		return memDetailCache
	}

	detail := &MemoryDetail{}

	// Cache & buffers from /proc/meminfo (already parsed in readMemInfo but
	// we re-read here so this function is self-contained and independently cached).
	if mi := readMemInfo(); mi != nil {
		detail.CachedMB = mi.CachedMB
		detail.BuffersMB = mi.BuffersMB
	}

	// Enumerate /proc for numeric PID directories.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		memDetailCache = detail
		memDetailTime = time.Now()
		return detail
	}

	type rawProc struct {
		pid   int
		rssMB float64
		name  string
		state string
	}

	procs := make([]rawProc, 0, 256)

	// Reuse a single scanner buffer across all /proc/PID/status reads
	// instead of allocating a new []byte per os.ReadFile (hundreds of processes).
	scanBuf := make([]byte, 0, 4096)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}

		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		f, err := os.Open(statusPath)
		if err != nil {
			continue // process may have exited
		}

		var name, state string
		var rssKB int64
		found := 0

		scanner := bufio.NewScanner(f)
		scanner.Buffer(scanBuf, 4096)
		for scanner.Scan() {
			line := scanner.Text()
			// Fast prefix check before calling Fields (avoids allocation).
			if len(line) < 5 {
				continue
			}
			switch {
			case strings.HasPrefix(line, "Name:"):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					name = fields[1]
					found++
				}
			case strings.HasPrefix(line, "State:"):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					state = fields[1]
					found++
				}
			case strings.HasPrefix(line, "VmRSS:"):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					rssKB, _ = strconv.ParseInt(fields[1], 10, 64)
					found++
				}
			}
			if found >= 3 {
				break // got all fields — stop reading
			}
		}
		f.Close()

		if rssKB <= 0 {
			continue
		}

		procs = append(procs, rawProc{
			pid:   pid,
			rssMB: float64(rssKB) / 1024,
			name:  name,
			state: state,
		})
	}

	// Sort descending by RSS — O(n log n).
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].rssMB > procs[j].rssMB
	})

	// Keep top 25.
	limit := 25
	if len(procs) < limit {
		limit = len(procs)
	}
	result := make([]ProcessMemInfo, limit)
	for i := 0; i < limit; i++ {
		result[i] = ProcessMemInfo{
			PID:   procs[i].pid,
			Name:  procs[i].name,
			RssMB: math.Round(procs[i].rssMB*10) / 10,
			State: procs[i].state,
		}
	}
	detail.TopProcesses = result

	memDetailCache = detail
	memDetailTime = time.Now()
	releaseMemory()
	return detail
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
// Uses a scanner to avoid allocating the full file into a []byte.
func readSelfProcess() *ProcessInfo {
	info := &ProcessInfo{
		PID: os.Getpid(),
	}

	f, err := os.Open("/proc/self/status")
	if err != nil {
		return info
	}
	defer f.Close()

	found := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseFloat(fields[1], 64)
				info.MemMB = val / 1024 // kB -> MB
				found++
			}
		} else if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.NumThreads, _ = strconv.Atoi(fields[1])
				found++
			}
		}
		if found >= 2 {
			break
		}
	}
	return info
}

// readServices checks the status of key services.
// Runs all systemctl calls in parallel to reduce latency (6 sequential → 6 concurrent).
func readServices() []ServiceInfo {
	serviceNames := []string{"serverpilot", "docker", "nginx"}
	services := make([]ServiceInfo, len(serviceNames))

	var wg sync.WaitGroup
	for i, name := range serviceNames {
		wg.Add(1)
		go func(idx int, svcName string) {
			defer wg.Done()
			svc := ServiceInfo{Name: svcName}

			// Check if active.
			cmd := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", svcName)
			svc.Active = cmd.Run() == nil
			if svc.Active {
				svc.Status = "running"
			} else {
				svc.Status = "stopped"
			}

			// Get memory usage from systemctl show.
			cmd = exec.Command("/usr/bin/systemctl", "show", svcName, "--property=MemoryCurrent", "--no-pager")
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

			services[idx] = svc
		}(i, name)
	}
	wg.Wait()

	return services
}
