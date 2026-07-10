package deps

import "testing"

func TestComposePluginPackageForDistro(t *testing.T) {
	// distroID reads /etc/os-release; on dev machines this may be darwin/unknown.
	pkg := ComposePluginPackageForDistro()
	id := distroID()
	switch id {
	case "debian", "ubuntu":
		if pkg != ComposePluginPackage {
			t.Fatalf("expected %q for %s, got %q", ComposePluginPackage, id, pkg)
		}
	default:
		if pkg != "" {
			t.Fatalf("expected empty package for %s, got %q", id, pkg)
		}
	}
}
