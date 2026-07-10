package deps

import (
	"strings"
	"testing"
)

func TestComposePluginArch(t *testing.T) {
	arch, err := composePluginArch()
	if err != nil {
		t.Fatalf("composePluginArch: %v", err)
	}
	switch arch {
	case "x86_64", "aarch64", "armv7":
	default:
		t.Fatalf("unexpected arch %q", arch)
	}
}

func TestComposePluginBinaryPath(t *testing.T) {
	path, err := composePluginBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected path")
	}
	if !strings.HasSuffix(path, "/docker-compose") {
		t.Fatalf("unexpected path %q", path)
	}
}
