package docker

import "testing"

func TestPruneModeValid(t *testing.T) {
	cases := []struct {
		mode PruneMode
		ok   bool
	}{
		{PruneSafe, true},
		{PruneImages, true},
		{PruneVolumes, true},
		{PruneAggressive, true},
		{PruneBuilder, true},
		{PruneMode("evil"), false},
		{PruneMode(""), false},
	}
	for _, tc := range cases {
		if got := tc.mode.Valid(); got != tc.ok {
			t.Fatalf("mode %q valid=%v want %v", tc.mode, got, tc.ok)
		}
	}
}

func TestPruneModeDockerArgsFixed(t *testing.T) {
	cases := map[PruneMode][]string{
		PruneSafe:       {"system", "prune", "-f"},
		PruneImages:     {"system", "prune", "-a", "-f"},
		PruneVolumes:    {"volume", "prune", "-f"},
		PruneAggressive: {"system", "prune", "-a", "--volumes", "-f"},
		PruneBuilder:    {"builder", "prune", "-f"},
	}
	for mode, want := range cases {
		got, err := mode.dockerArgs()
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if len(got) != len(want) {
			t.Fatalf("mode %q args=%v want %v", mode, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("mode %q arg[%d]=%q want %q", mode, i, got[i], want[i])
			}
		}
	}
}

func TestPruneModesMetadata(t *testing.T) {
	modes := PruneModes()
	if len(modes) != 5 {
		t.Fatalf("expected 5 prune modes, got %d", len(modes))
	}
	for _, m := range modes {
		if !m.Mode.Valid() {
			t.Fatalf("metadata mode %q not valid", m.Mode)
		}
		if m.Mode.RequiresTypeConfirm() != m.RequiresTypeConfirm {
			t.Fatalf("mode %q type-confirm mismatch", m.Mode)
		}
	}
}

func TestSanitizePruneOutput(t *testing.T) {
	if got := sanitizePruneOutput(""); got == "" {
		t.Fatal("expected non-empty default message")
	}
	long := stringsRepeat("x", 3000)
	got := sanitizePruneOutput(long)
	if len(got) <= 2048 {
		t.Fatalf("expected truncated output, len=%d", len(got))
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
