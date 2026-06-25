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
