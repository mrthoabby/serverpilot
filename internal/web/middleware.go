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
