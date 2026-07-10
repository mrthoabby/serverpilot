package templates

import "testing"

func TestDefaultOptionsMCP(t *testing.T) {
	opts := DefaultOptions(MCP)
	if !opts.SSE {
		t.Fatal("expected MCP SSE enabled by default")
	}
	if !opts.ResponseBufferingOff {
		t.Fatal("expected MCP response buffering off by default")
	}
	if opts.BodySize != "50m" {
		t.Fatalf("expected MCP body size 50m, got %q", opts.BodySize)
	}
}

func TestValidateOptionsRejectsInvalidBodySize(t *testing.T) {
	err := ValidateOptions(TemplateOptions{BodySize: "not-a-size"})
	if err == nil {
		t.Fatal("expected invalid body size error")
	}
}

func TestMergeOptionsRateLimit(t *testing.T) {
	opts, err := MergeOptions(API, TemplateOptions{
		RateLimitEnabled: true,
		RateLimitRate:    "5r/s",
		RateLimitBurst:   10,
	})
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !opts.RateLimitEnabled || opts.RateLimitRate != "5r/s" || opts.RateLimitBurst != 10 {
		t.Fatalf("unexpected merged options: %#v", opts)
	}
}

func TestRateLimitZoneNameSanitizesDomain(t *testing.T) {
	got := RateLimitZoneName("API.Example.COM")
	if got != "sp_rl_api_example_com" {
		t.Fatalf("unexpected zone name: %q", got)
	}
}
