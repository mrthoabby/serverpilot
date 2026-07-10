package compose

import "testing"

func TestValidateSocketImageRef(t *testing.T) {
	if err := validateSocketImageRef("ghcr.io/org/app:v1.2.3"); err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
	if err := validateSocketImageRef(""); err == nil {
		t.Fatal("expected empty ref error")
	}
	if err := validateSocketImageRef("bad\nref"); err == nil {
		t.Fatal("expected control char error")
	}
}

func TestValidateSocketSecret(t *testing.T) {
	if err := validateSocketSecret(""); err != nil {
		t.Fatal("empty secret should be allowed")
	}
	if err := validateSocketSecret("token\x00"); err == nil {
		t.Fatal("expected control char error")
	}
}
