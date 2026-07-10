package mapper

import "testing"

func TestExtractPortFromProxyPass(t *testing.T) {
	tests := map[string]string{
		"http://127.0.0.1:3000/":    "3000",
		"http://localhost:8080/api": "8080",
		"http://127.0.0.1:3000":     "3000",
	}
	for in, want := range tests {
		got, err := extractPortFromProxyPass(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestExtractPortFromProxyPassRejectsInvalid(t *testing.T) {
	if _, err := extractPortFromProxyPass("http://127.0.0.1:notaport/"); err == nil {
		t.Fatal("expected error for invalid proxy_pass port")
	}
}

func TestMatchesProxyPassExactPort(t *testing.T) {
	if !matchesProxyPass("http://127.0.0.1:3000/", "3000") {
		t.Fatal("expected exact port match")
	}
	if matchesProxyPass("http://127.0.0.1:3001/", "3000") {
		t.Fatal("expected port mismatch")
	}
}
