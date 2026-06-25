package sysinfo

import "testing"

func TestParseDURootLines(t *testing.T) {
	output := "87630\t/\n45000\t/var\n2784\t/usr\n1200\t/home\n500\t/opt\n"
	entries, totalMB := parseDURootLines(output)

	if totalMB != 87630 {
		t.Fatalf("totalMB = %v, want 87630", totalMB)
	}
	if len(entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4", len(entries))
	}
	if entries[0].Path != "/var" || entries[0].SizeMB != 45000 {
		t.Fatalf("first entry = %+v, want /var 45000", entries[0])
	}
}

func TestParseDURootLinesSkipsSmallEntries(t *testing.T) {
	output := "100\t/\n0.5\t/run\n50\t/tmp\n"
	entries, _ := parseDURootLines(output)
	if len(entries) != 1 || entries[0].Path != "/tmp" {
		t.Fatalf("entries = %+v, want only /tmp", entries)
	}
}

func TestParseDockerContainerWritableSize(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"1.2GB (virtual 1.5GB)", 1200},
		{"232kB", 0.232},
		{"0B", 0},
		{"", 0},
	}
	for _, tc := range tests {
		got := parseDockerContainerWritableSize(tc.in)
		if got != tc.want {
			t.Fatalf("parseDockerContainerWritableSize(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseMountVolumeNames(t *testing.T) {
	mounts := "mydata:/var/lib/mysql,otherdb:/data,/host/path:/mnt,shared-vol:/shared"
	got := parseMountVolumeNames(mounts)
	want := []string{"mydata", "otherdb", "shared-vol"}
	if len(got) != len(want) {
		t.Fatalf("parseMountVolumeNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseMountVolumeNames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseDockerSystemDFTable(t *testing.T) {
	output := `TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          25        10        23.04GB   15.53GB (67%)
Containers      7         4         1.042GB   800MB (76%)
Local Volumes   5         3         2.5GB     1GB (40%)
Build Cache     15        0         500MB     500MB
`
	stats := parseDockerSystemDFTable(output)
	if len(stats) != 4 {
		t.Fatalf("len(stats) = %d, want 4", len(stats))
	}
	if stats[0].Type != "Images" || stats[0].SizeMB != 23040 {
		t.Fatalf("Images = %+v, want 23040 MB", stats[0])
	}
	if stats[2].Type != "Local Volumes" || stats[2].SizeMB != 2500 {
		t.Fatalf("Local Volumes = %+v, want 2500 MB", stats[2])
	}
	if stats[3].ReclaimMB != 500 {
		t.Fatalf("Build Cache reclaim = %v, want 500", stats[3].ReclaimMB)
	}
}

func TestParseDockerVolumeSizesFromOutput(t *testing.T) {
	output := "Images space usage:\n\nLocal Volumes space usage:\n\nVOLUME NAME   LINKS   SIZE\nmydata        1       1.2GB\nunused_vol    0       512MB\n\nBuild cache usage:\n"
	sizes := parseDockerVolumeSizesFromOutput(output)
	if sizes["mydata"] != 1200 {
		t.Fatalf("mydata size = %v, want 1200", sizes["mydata"])
	}
	if sizes["unused_vol"] != 512 {
		t.Fatalf("unused_vol size = %v, want 512", sizes["unused_vol"])
	}
}
