package web

import (
	"log"
	"net/http"
	"time"
)

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

		if s.config.SSLEnabled {
			// HSTS: tell browsers to always use HTTPS for 1 year, include subdomains.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// Defense-in-depth: if a request arrives over plain HTTP (X-Forwarded-Proto
			// set by nginx), redirect to HTTPS. This only triggers if nginx redirect
			// was somehow bypassed.
			if r.Header.Get("X-Forwarded-Proto") == "http" {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
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
