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
	// diskScanMaxDepth bounds how deep a timed-out directory is broken into
	// smaller pieces. Deeper trees split into finishable chunks so nothing is
	// silently dropped.
	diskScanMaxDepth       = 5
	diskScanDuCacheTTL     = 45 * time.Second
	diskScanDefaultWorkers = 4
	diskScanMaxWorkers     = 8
	diskScanMaxLeafTimeout = 4 * time.Minute
)

// scanJob is one unit of work in the priority scan pool. Every job rolls up
// into exactly one top-level "root" directory (e.g. /var/lib/docker -> /var).
type scanJob struct {
	path     string
	root     string
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

// rootProgress accumulates the running total for one top-level directory.
type rootProgress struct {
	root    string
	totalMB float64
	pending int  // outstanding jobs (this root + all descendants) still in flight
	partial bool // a leaf could not be measured even after retries
}

type duCacheEntry struct {
	sizeMB float64
	at     time.Time
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

// shouldDecomposeFirst fans a known-large directory into its children up front
// instead of running a single slow du over the whole tree.
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

// duTimeoutForDepth is generous: shallow jobs cover bigger trees so they get
// more time, deeper (smaller) jobs get less but still comfortable budgets.
func duTimeoutForDepth(depth int) time.Duration {
	switch {
	case depth <= 0:
		return 120 * time.Second
	case depth == 1:
		return 90 * time.Second
	case depth == 2:
		return 60 * time.Second
	default:
		return 45 * time.Second
	}
}

// cachedDuPathSummaryMB caches only successful results so a transient timeout is
// never remembered as a real measurement.
func cachedDuPathSummaryMB(path string, timeout time.Duration) (float64, bool) {
	duCacheMu.Lock()
	if hit, ok := duCache[path]; ok && time.Since(hit.at) < diskScanDuCacheTTL {
		duCacheMu.Unlock()
		return hit.sizeMB, false
	}
	duCacheMu.Unlock()

	sizeMB, partial := duPathSummaryMB(path, timeout)
	if !partial {
		duCacheMu.Lock()
		duCache[path] = duCacheEntry{sizeMB: sizeMB, at: time.Now()}
		duCacheMu.Unlock()
	}
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

func makeDiskRootEntry(path string, sizeMB float64, partial, scanning bool) DiskRootEntry {
	return DiskRootEntry{
		Path:     path,
		SizeMB:   math.Round(sizeMB*100) / 100,
		SizeGB:   math.Round(sizeMB/1024*100) / 100,
		Partial:  partial,
		Scanning: scanning,
	}
}

type diskScanEngine struct {
	onEntry  func(DiskRootEntry)
	workers  int
	jobs     scanJobHeap
	jobsMu   sync.Mutex
	jobsCond sync.Cond
	shutdown bool
	pending  int64
	done     chan struct{}
	doneOnce sync.Once

	roots  map[string]*rootProgress
	rootMu sync.Mutex
}

func newDiskScanEngine(onEntry func(DiskRootEntry)) *diskScanEngine {
	e := &diskScanEngine{
		onEntry: onEntry,
		workers: diskScanWorkerCount(),
		done:    make(chan struct{}),
		roots:   make(map[string]*rootProgress),
	}
	e.jobsCond.L = &e.jobsMu
	heap.Init(&e.jobs)
	return e
}

func (e *diskScanEngine) finishJob() {
	if atomic.AddInt64(&e.pending, -1) == 0 {
		e.doneOnce.Do(func() { close(e.done) })
	}
}

// scheduleRootJob registers the job against its root's pending counter and
// enqueues it. Global pending is bumped here so the engine knows when all work
// (including dynamically-spawned children) is complete.
func (e *diskScanEngine) scheduleRootJob(job scanJob) {
	e.rootMu.Lock()
	if rp, ok := e.roots[job.root]; ok {
		rp.pending++
	}
	e.rootMu.Unlock()

	atomic.AddInt64(&e.pending, 1)
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

// completeRootJob records the outcome of one job and emits a progressive update
// for its root. scanning stays true until the root has no outstanding jobs.
func (e *diskScanEngine) completeRootJob(root string, sizeMB float64, partial bool) {
	e.rootMu.Lock()
	rp, ok := e.roots[root]
	if !ok {
		e.rootMu.Unlock()
		return
	}
	rp.totalMB += sizeMB
	if partial {
		rp.partial = true
	}
	rp.pending--
	scanning := rp.pending > 0
	total := rp.totalMB
	isPartial := rp.partial
	e.rootMu.Unlock()

	e.onEntry(makeDiskRootEntry(root, total, isPartial, scanning))
}

// decompose fans a directory into its child directories, all rolling up into the
// same root. Returns false when there is nothing to split.
func (e *diskScanEngine) decompose(job *scanJob) bool {
	children, err := listScanChildPaths(job.path)
	if err != nil || len(children) == 0 {
		return false
	}
	for _, child := range children {
		e.scheduleRootJob(scanJob{
			path:     child,
			root:     job.root,
			priority: pathScanPriority(child) - job.depth,
			depth:    job.depth + 1,
		})
	}
	return true
}

// retryLeaf gives a directory that timed out a second, longer attempt before we
// give up on measuring it.
func retryLeaf(path string, prev time.Duration) (float64, bool) {
	longer := prev * 2
	if longer > diskScanMaxLeafTimeout {
		longer = diskScanMaxLeafTimeout
	}
	sizeMB, partial := duPathSummaryMB(path, longer)
	if !partial {
		duCacheMu.Lock()
		duCache[path] = duCacheEntry{sizeMB: sizeMB, at: time.Now()}
		duCacheMu.Unlock()
	}
	return sizeMB, partial
}

func (e *diskScanEngine) runJob(job *scanJob) {
	defer e.finishJob()

	// Known-large directories: split immediately instead of one slow walk.
	if job.depth == 0 && shouldDecomposeFirst(job.path) {
		if e.decompose(job) {
			e.completeRootJob(job.root, 0, false)
			return
		}
	}

	timeout := duTimeoutForDepth(job.depth)
	sizeMB, partial := cachedDuPathSummaryMB(job.path, timeout)

	if partial {
		// Break the slow directory into smaller, finishable pieces.
		if job.depth < diskScanMaxDepth && e.decompose(job) {
			e.completeRootJob(job.root, 0, false)
			return
		}
		// Can't split further (no subdirs / max depth) — be patient and retry
		// once with a much longer budget before marking it unmeasured.
		sizeMB, partial = retryLeaf(job.path, timeout)
	}

	if partial {
		// Never inject a bogus 0; flag the root as partial but keep its real
		// accumulated total.
		e.completeRootJob(job.root, 0, true)
		return
	}

	e.completeRootJob(job.root, sizeMB, false)
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

func (e *diskScanEngine) run(paths []string) error {
	for _, p := range paths {
		e.roots[p] = &rootProgress{root: p}
	}

	// Schedule all initial jobs BEFORE starting workers so global pending can
	// never momentarily hit zero and close `done` prematurely.
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Slice(sorted, func(i, j int) bool {
		return pathScanPriority(sorted[i]) > pathScanPriority(sorted[j])
	})
	for _, p := range sorted {
		e.scheduleRootJob(scanJob{path: p, root: p, priority: pathScanPriority(p), depth: 0})
	}

	for i := 0; i < e.workers; i++ {
		go e.worker()
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
	engine := newDiskScanEngine(onEntry)
	return engine.run(paths)
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

// DiskRootScanStream scans top-level directories with intelligent work
// distribution, emitting progressive per-root updates until each root completes.
func DiskRootScanStream(onEntry func(DiskRootEntry)) error {
	paths, err := DiskRootScanPathsSorted()
	if err != nil {
		return fmt.Errorf("root scan failed: %w", err)
	}
	return runPriorityDiskScan(paths, onEntry)
}
