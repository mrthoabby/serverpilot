package sysinfo

import (
	"container/heap"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	diskScanMaxDepth       = 2
	diskScanDuCacheTTL     = 45 * time.Second
	diskScanDefaultWorkers = 4
	diskScanMaxWorkers     = 8
)

// scanJob is one unit of work in the priority scan pool.
type scanJob struct {
	path     string
	parent   string
	priority int
	depth    int
	index    int
}

type scanJobHeap []*scanJob

func (h scanJobHeap) Len() int           { return len(h) }
func (h scanJobHeap) Less(i, j int) bool { return h[i].priority > h[j].priority }
func (h scanJobHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *scanJobHeap) Push(x interface{}) {
	n := len(*h)
	job := x.(*scanJob)
	job.index = n
	*h = append(*h, job)
}
func (h *scanJobHeap) Pop() interface{} {
	old := *h
	n := len(old)
	job := old[n-1]
	old[n-1] = nil
	job.index = -1
	*h = old[:n-1]
	return job
}

type parentAggregate struct {
	path    string
	totalMB float64
	pending int
	partial bool
}

type duCacheEntry struct {
	sizeMB  float64
	partial bool
	at      time.Time
}

var (
	duCacheMu sync.Mutex
	duCache   = make(map[string]duCacheEntry)
)

// pathScanPriority assigns higher values to paths that usually dominate disk usage.
func pathScanPriority(path string) int {
	switch path {
	case "/var/lib/docker":
		return 120
	case "/var/lib":
		return 115
	case "/var":
		return 110
	case "/usr":
		return 100
	case "/home":
		return 90
	case "/opt":
		return 80
	case "/var/log":
		return 75
	case "/root":
		return 60
	case "/srv":
		return 55
	case "/var/cache":
		return 50
	case "/tmp":
		return 40
	case "/snap":
		return 35
	case "/boot":
		return 30
	default:
		if strings.HasPrefix(path, "/var/") {
			return 70
		}
		return 10
	}
}

func shouldDecomposeFirst(path string) bool {
	switch path {
	case "/var", "/usr":
		return true
	default:
		return false
	}
}

func diskScanWorkerCount() int {
	n := runtime.NumCPU()
	if n < diskScanDefaultWorkers {
		n = diskScanDefaultWorkers
	}
	if n > diskScanMaxWorkers {
		n = diskScanMaxWorkers
	}
	return n
}

func duTimeoutForDepth(depth int) time.Duration {
	switch {
	case depth <= 0:
		return 75 * time.Second
	case depth == 1:
		return 45 * time.Second
	default:
		return 25 * time.Second
	}
}

func cachedDuPathSummaryMB(path string, timeout time.Duration) (float64, bool) {
	duCacheMu.Lock()
	if hit, ok := duCache[path]; ok && time.Since(hit.at) < diskScanDuCacheTTL {
		duCacheMu.Unlock()
		return hit.sizeMB, hit.partial
	}
	duCacheMu.Unlock()

	sizeMB, partial := duPathSummaryMB(path, timeout)

	duCacheMu.Lock()
	duCache[path] = duCacheEntry{sizeMB: sizeMB, partial: partial, at: time.Now()}
	duCacheMu.Unlock()
	return sizeMB, partial
}

func listScanChildPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(dir, de.Name()))
	}
	sort.Slice(paths, func(i, j int) bool {
		return pathScanPriority(paths[i]) > pathScanPriority(paths[j])
	})
	return paths, nil
}

func makeDiskRootEntry(path string, sizeMB float64, partial bool) DiskRootEntry {
	return DiskRootEntry{
		Path:    path,
		SizeMB:  math.Round(sizeMB*100) / 100,
		SizeGB:  math.Round(sizeMB/1024*100) / 100,
		Partial: partial,
	}
}

type diskScanEngine struct {
	onEntry    func(DiskRootEntry)
	workers    int
	jobs       scanJobHeap
	jobsMu     sync.Mutex
	jobsCond   sync.Cond
	shutdown   bool
	pending    int64
	done       chan struct{}
	doneOnce   sync.Once
	aggregates map[string]*parentAggregate
	aggMu      sync.Mutex
}

func newDiskScanEngine(onEntry func(DiskRootEntry)) *diskScanEngine {
	e := &diskScanEngine{
		onEntry:    onEntry,
		workers:    diskScanWorkerCount(),
		done:       make(chan struct{}),
		aggregates: make(map[string]*parentAggregate),
	}
	e.jobsCond.L = &e.jobsMu
	heap.Init(&e.jobs)
	return e
}

func (e *diskScanEngine) trackJob() {
	atomic.AddInt64(&e.pending, 1)
}

func (e *diskScanEngine) finishJob() {
	if atomic.AddInt64(&e.pending, -1) == 0 {
		e.doneOnce.Do(func() { close(e.done) })
	}
}

func (e *diskScanEngine) pushJob(job scanJob) {
	e.trackJob()
	e.jobsMu.Lock()
	heap.Push(&e.jobs, &job)
	e.jobsCond.Signal()
	e.jobsMu.Unlock()
}

func (e *diskScanEngine) popJob() (*scanJob, bool) {
	e.jobsMu.Lock()
	defer e.jobsMu.Unlock()
	for e.jobs.Len() == 0 && !e.shutdown {
		e.jobsCond.Wait()
	}
	if e.jobs.Len() == 0 {
		return nil, false
	}
	return heap.Pop(&e.jobs).(*scanJob), true
}

func (e *diskScanEngine) registerAggregate(parent string, childCount int) {
	e.aggMu.Lock()
	e.aggregates[parent] = &parentAggregate{path: parent, pending: childCount}
	e.aggMu.Unlock()
}

func (e *diskScanEngine) contributeToParent(parent string, sizeMB float64, partial bool) {
	if parent == "" {
		return
	}
	e.aggMu.Lock()
	agg, ok := e.aggregates[parent]
	if !ok {
		e.aggMu.Unlock()
		return
	}
	agg.totalMB += sizeMB
	if partial {
		agg.partial = true
	}
	agg.pending--
	done := agg.pending <= 0
	total := agg.totalMB
	isPartial := agg.partial
	parentPath := agg.path
	if done {
		delete(e.aggregates, parent)
	}
	e.aggMu.Unlock()

	e.onEntry(makeDiskRootEntry(parentPath, total, isPartial && !done))
}

func (e *diskScanEngine) tryDecompose(job *scanJob) bool {
	children, err := listScanChildPaths(job.path)
	if err != nil || len(children) == 0 {
		return false
	}

	e.registerAggregate(job.path, len(children))
	for _, child := range children {
		e.pushJob(scanJob{
			path:     child,
			parent:   job.path,
			priority: pathScanPriority(child) - job.depth,
			depth:    job.depth + 1,
		})
	}
	return true
}

func (e *diskScanEngine) runJob(job *scanJob) {
	defer e.finishJob()

	if shouldDecomposeFirst(job.path) && job.depth == 0 {
		if e.tryDecompose(job) {
			return
		}
	}

	sizeMB, partial := cachedDuPathSummaryMB(job.path, duTimeoutForDepth(job.depth))

	if partial && job.depth < diskScanMaxDepth {
		if e.tryDecompose(job) {
			return
		}
	}

	if sizeMB < 0.01 && !partial {
		if job.parent != "" {
			e.contributeToParent(job.parent, 0, false)
		}
		return
	}

	if job.parent != "" {
		e.contributeToParent(job.parent, sizeMB, partial)
		return
	}

	e.onEntry(makeDiskRootEntry(job.path, sizeMB, partial))
}

func (e *diskScanEngine) worker() {
	for {
		job, ok := e.popJob()
		if !ok {
			return
		}
		e.runJob(job)
	}
}

func (e *diskScanEngine) run(initial []scanJob) error {
	for i := 0; i < e.workers; i++ {
		go e.worker()
	}
	for _, job := range initial {
		j := job
		e.pushJob(j)
	}

	<-e.done

	e.jobsMu.Lock()
	e.shutdown = true
	e.jobsMu.Unlock()
	e.jobsCond.Broadcast()
	return nil
}

func runPriorityDiskScan(paths []string, onEntry func(DiskRootEntry)) error {
	if len(paths) == 0 {
		return nil
	}
	jobs := make([]scanJob, 0, len(paths))
	for _, path := range paths {
		jobs = append(jobs, scanJob{
			path:     path,
			priority: pathScanPriority(path),
			depth:    0,
		})
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].priority > jobs[j].priority })
	engine := newDiskScanEngine(onEntry)
	return engine.run(jobs)
}

// DiskRootScanPathsSorted returns top-level scan paths ordered by likely size (highest first).
func DiskRootScanPathsSorted() ([]string, error) {
	paths, err := DiskRootScanPaths()
	if err != nil {
		return nil, err
	}
	sort.Slice(paths, func(i, j int) bool {
		return pathScanPriority(paths[i]) > pathScanPriority(paths[j])
	})
	return paths, nil
}

// DiskRootScanStream scans top-level directories with intelligent work distribution.
func DiskRootScanStream(onEntry func(DiskRootEntry)) error {
	paths, err := DiskRootScanPathsSorted()
	if err != nil {
		return fmt.Errorf("root scan failed: %w", err)
	}
	return runPriorityDiskScan(paths, onEntry)
}
