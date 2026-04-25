package web

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Scanner / bot detection logger ──────────────────────────────────────────
//
// Requests that reach /api/ without the three client identity headers are
// logged here: they are not served by the legitimate dashboard frontend and
// are likely scanners, bots, or someone probing the server directly.
//
// The log file path is hardcoded — it never comes from user input, so there
// is no path-traversal risk (CWE-22). Each line is sanitised before writing
// to prevent log-injection (CWE-117).

const scannerLogPath = "/var/log/serverpilot-scanners.log"

// Expected values for the three client identity headers.
const (
	spClientValue = "dashboard"
	spBuildValue  = "1"
	spSourceValue = "ui"
)

var (
	scannerLogMu   sync.Mutex
	scannerLogFile *os.File
)

// initScannerLogger opens (or creates) the scanner log file for appending.
// Non-fatal — if the file cannot be opened the middleware still runs but
// silently skips writing.
func initScannerLogger() {
	f, err := os.OpenFile(scannerLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("scanner logger: cannot open %s: %v (bot detection logging disabled)", scannerLogPath, err)
		return
	}
	scannerLogFile = f
	log.Printf("scanner logger: writing to %s", scannerLogPath)
}

// logScannerRequest appends a single line for a suspicious request.
// It is safe to call from concurrent goroutines.
func logScannerRequest(r *http.Request, missing []string) {
	scannerLogMu.Lock()
	defer scannerLogMu.Unlock()
	if scannerLogFile == nil {
		return
	}
	ip := extractClientIP(r)
	ua := sanitizeLogField(r.Header.Get("User-Agent"), 200)
	line := fmt.Sprintf("%s | ip=%-20s | %-6s %s | missing=%s | ua=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		ip,
		r.Method,
		r.URL.Path,
		strings.Join(missing, ","),
		ua,
	)
	if _, err := fmt.Fprint(scannerLogFile, line); err != nil {
		log.Printf("scanner logger: write error: %v", err)
	}
}

// extractClientIP returns the best-effort client IP from the request.
// When the server is behind nginx, X-Real-IP carries the actual client address.
func extractClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return sanitizeLogField(ip, 45)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Only take the first address — the rest may be added by intermediate proxies.
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			xff = xff[:idx]
		}
		return sanitizeLogField(strings.TrimSpace(xff), 45)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sanitizeLogField removes control characters (including newlines) to prevent
// log injection (CWE-117) and truncates to maxLen bytes.
func sanitizeLogField(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > maxLen {
		return result[:maxLen]
	}
	return result
}

// ClientHeaderMiddleware checks that every /api/ request carries the three
// client identity headers that the legitimate dashboard always sends.
// Requests missing any header are still served (this is detection-only, not
// blocking), but their IP and request details are written to the scanner log.
func (s *Server) ClientHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			var missing []string
			if r.Header.Get("X-SP-Client") != spClientValue {
				missing = append(missing, "X-SP-Client")
			}
			if r.Header.Get("X-SP-Build") != spBuildValue {
				missing = append(missing, "X-SP-Build")
			}
			if r.Header.Get("X-SP-Source") != spSourceValue {
				missing = append(missing, "X-SP-Source")
			}
			if len(missing) > 0 {
				logScannerRequest(r, missing)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it supports flushing (required for SSE streaming).
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the original ResponseWriter so that type assertions (e.g. http.Flusher) work through the wrapper.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// authMiddleware checks for a valid session cookie on protected routes.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "authentication required"})
			return
		}

		_, valid := s.sessionStore.ValidateSession(cookie.Value)
		if !valid {
			writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid or expired session"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs HTTP requests with method, path, status, and duration.
// Sensitive data (query params, headers, body) is not logged.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.statusCode, duration)
	})
}

// SecurityMiddleware adds security headers to all responses.
// When SSL is enabled, it enforces HSTS, prevents downgrade attacks, and blocks
// the page from being framed. It also blocks requests that arrive over plain HTTP
// when the server knows it should be behind HTTPS (defense-in-depth — nginx also
// handles the redirect, but this catches direct-to-Go requests).
func (s *Server) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always set baseline security headers.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if s.config.SSLEnabled && s.config.Domain != "" {
			// HSTS: tell browsers to always use HTTPS for 1 year, include subdomains.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// Defense-in-depth: if a request arrives over plain HTTP (X-Forwarded-Proto
			// set by nginx), redirect to HTTPS.
			proto := r.Header.Get("X-Forwarded-Proto")
			if proto == "http" {
				target := "https://" + s.config.Domain + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}

			// Block direct access that bypasses nginx entirely.
			// If SSL is enabled, legitimate requests come through nginx which sets
			// X-Forwarded-Proto. A missing header means someone is hitting the Go
			// server directly — only allow from loopback (nginx on same host).
			if proto == "" {
				remoteIP := r.RemoteAddr
				if host, _, err := net.SplitHostPort(remoteIP); err == nil {
					remoteIP = host
				}
				if !isLoopback(remoteIP) {
					log.Printf("Blocked direct access from %s (SSL enabled, must go through nginx)", r.RemoteAddr)
					http.Error(w, "Direct access not allowed. Use https://"+s.config.Domain, http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isLoopback returns true if the IP is a loopback address (127.x.x.x or ::1).
func isLoopback(ip string) bool {
	if strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "localhost" {
		return true
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// RecoveryMiddleware recovers from panics and returns a 500 error.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v", err)
				writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
