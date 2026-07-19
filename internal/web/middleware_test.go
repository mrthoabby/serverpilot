package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"nhooyr.io/websocket"
)

func TestLoggingMiddlewarePreservesWebSocketHijacker(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.CloseNow()

		msgType, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if err := conn.Write(r.Context(), msgType, append([]byte("echo:"), data...)); err != nil {
			return
		}
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("websocket dial through logging middleware failed: %v", err)
	}
	defer conn.CloseNow()

	if err := conn.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	if got, want := string(data), "echo:ping"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestSecurityMiddlewareSetsDashboardCSP(t *testing.T) {
	srv := &Server{config: &auth.Config{}}
	handler := srv.SecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP missing connect-src self: %q", csp)
	}
	if !strings.Contains(csp, "https://cdn.jsdelivr.net") {
		t.Fatalf("CSP missing jsdelivr: %q", csp)
	}
}
