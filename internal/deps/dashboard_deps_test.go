package deps

import "testing"

func TestListDashboardDependenciesIncludesCore(t *testing.T) {
	items := ListDashboardDependencies()
	if len(items) < 2 {
		t.Fatalf("expected at least docker and nginx, got %d", len(items))
	}
	if items[0].ID != "docker" || items[1].ID != "nginx" {
		t.Fatalf("unexpected order: %#v", items[:2])
	}
}

func TestACLToolsInstalled(t *testing.T) {
	_ = ACLToolsInstalled()
}
