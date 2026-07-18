package compose

import (
	"strings"
	"testing"
	"time"
)

func TestParseStrategy(t *testing.T) {
	cases := map[string]string{
		"":           StrategyRolling,
		"rolling":    StrategyRolling,
		"blue-green": StrategyBlueGreen,
		"bluegreen":  StrategyBlueGreen,
		"bg":         StrategyBlueGreen,
		"BLUE-GREEN": StrategyBlueGreen,
	}
	for in, want := range cases {
		if got := ParseStrategy(in); got != want {
			t.Fatalf("ParseStrategy(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOppositeAndNormalizeColor(t *testing.T) {
	if oppositeColor(ColorBlue) != ColorGreen {
		t.Fatal("blue should flip to green")
	}
	if oppositeColor(ColorGreen) != ColorBlue {
		t.Fatal("green should flip to blue")
	}
	if normalizeColor("") != ColorBlue {
		t.Fatal("empty color should default to blue")
	}
	if normalizeColor("GREEN") != ColorGreen {
		t.Fatal("green normalization failed")
	}
}

func TestColorProjectName(t *testing.T) {
	if got := colorProjectName("shop", ColorGreen); got != "shop__green" {
		t.Fatalf("unexpected project name: %s", got)
	}
}

func TestAnalysisAllowsBlueGreenRejectsMounts(t *testing.T) {
	err := analysisAllowsBlueGreen(&AnalyzeResult{
		Mounts: []MountSpec{{Type: "volume", Supported: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "persistent mounts") {
		t.Fatalf("expected persistent mount rejection, got %v", err)
	}
	if analysisAllowsBlueGreen(&AnalyzeResult{}) != nil {
		t.Fatal("expected stateless stack to pass")
	}
}

func TestEndpointKeyAndPortMap(t *testing.T) {
	ep := Endpoint{Service: "app", ContainerPort: "8080", Protocol: "tcp", HostPort: 3100}
	key := endpointKey(ep)
	if key != "app:8080/tcp" {
		t.Fatalf("unexpected key: %s", key)
	}
	m := endpointPortMap([]Endpoint{ep})
	if m[key] != 3100 {
		t.Fatalf("unexpected port map: %v", m)
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	if parseDurationOrDefault("", defaultHealthWait) != defaultHealthWait {
		t.Fatal("empty should use fallback")
	}
	got := parseDurationOrDefault("30s", defaultHealthWait)
	if got != 30*time.Second {
		t.Fatalf("expected 30s, got %v", got)
	}
}
