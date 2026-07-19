package docker

import "testing"

func TestValidateContainerRef(t *testing.T) {
	tests := []struct {
		ref string
		ok  bool
	}{
		{"", false},
		{"../etc/passwd", false},
		{"my-api", true},
		{"my_api-1", true},
		{"abc123def456", true},
		{"-bad", false},
	}
	for _, tc := range tests {
		err := ValidateContainerRef(tc.ref)
		if tc.ok && err != nil {
			t.Fatalf("ValidateContainerRef(%q) unexpected error: %v", tc.ref, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("ValidateContainerRef(%q) expected error", tc.ref)
		}
	}
}

func TestStripContainerColorSuffix(t *testing.T) {
	if got := stripContainerColorSuffix("api__green"); got != "api" {
		t.Fatalf("stripContainerColorSuffix = %q, want api", got)
	}
	if got := stripContainerColorSuffix("api"); got != "api" {
		t.Fatalf("stripContainerColorSuffix = %q, want api", got)
	}
}
