package sysinfo

import "testing"

func TestPathScanPriority(t *testing.T) {
	if pathScanPriority("/var/lib/docker") <= pathScanPriority("/var") {
		t.Fatalf("docker lib should outrank /var")
	}
	if pathScanPriority("/var") <= pathScanPriority("/tmp") {
		t.Fatalf("/var should outrank /tmp")
	}
	if pathScanPriority("/var/log") <= pathScanPriority("/boot") {
		t.Fatalf("/var/log should outrank /boot")
	}
}

func TestShouldDecomposeFirst(t *testing.T) {
	if !shouldDecomposeFirst("/var") || !shouldDecomposeFirst("/usr") {
		t.Fatal("expected /var and /usr to decompose first")
	}
	if shouldDecomposeFirst("/home") {
		t.Fatal("/home should not decompose first")
	}
}

func TestDiskScanWorkerCount(t *testing.T) {
	n := diskScanWorkerCount()
	if n < diskScanDefaultWorkers || n > diskScanMaxWorkers {
		t.Fatalf("worker count %d out of range", n)
	}
}

func TestDuTimeoutForDepth(t *testing.T) {
	if duTimeoutForDepth(0) <= duTimeoutForDepth(1) {
		t.Fatal("depth 0 should allow longer timeout")
	}
	if duTimeoutForDepth(1) <= duTimeoutForDepth(2) {
		t.Fatal("shallower depth should allow longer timeout")
	}
}

func TestDiskRootScanPathsSorted(t *testing.T) {
	// Uses live filesystem; on macOS / may differ but should not error.
	paths, err := DiskRootScanPathsSorted()
	if err != nil {
		t.Fatalf("DiskRootScanPathsSorted: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one path")
	}
	for i := 1; i < len(paths); i++ {
		if pathScanPriority(paths[i-1]) < pathScanPriority(paths[i]) {
			t.Fatalf("paths not sorted by priority: %v", paths)
		}
	}
}

func TestRunPriorityDiskScanEmpty(t *testing.T) {
	if err := runPriorityDiskScan(nil, func(DiskRootEntry) {}); err != nil {
		t.Fatalf("empty scan: %v", err)
	}
}
