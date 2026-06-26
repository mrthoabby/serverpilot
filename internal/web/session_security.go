package web

import (
	"net"
	"net/http"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
)

const (
	legacySessionCookieName = "sp_session"
	secureSessionCookieName = "__Host-sp_session"
)

func (s *Server) preferredSessionCookieName() string {
	if s.config.SSLEnabled {
		return secureSessionCookieName
	}
	return legacySessionCookieName
}

func (s *Server) currentSessionToken(r *http.Request) (string, bool) {
	names := []string{s.preferredSessionCookieName(), legacySessionCookieName, secureSessionCookieName}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		cookie, err := r.Cookie(name)
		if err == nil && cookie.Value != "" {
			return cookie.Value, true
		}
	}
	return "", false
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	cookieSecure := s.config.SSLEnabled
	cookieSameSite := http.SameSiteLaxMode
	if cookieSecure {
		cookieSameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.preferredSessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
		MaxAge:   int(auth.SessionMaxAge.Seconds()),
	})
	// When switching from HTTP to HTTPS, expire the old non-prefixed cookie.
	if cookieSecure {
		http.SetCookie(w, expiredSessionCookie(legacySessionCookieName, false))
	}
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, expiredSessionCookie(legacySessionCookieName, false))
	http.SetCookie(w, expiredSessionCookie(secureSessionCookieName, true))
}

func expiredSessionCookie(name string, secure bool) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   -1,
	}
}

func (s *Server) reauthMiddleware(next http.Handler, requireSecure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireSecure && !requestIsSecureEnough(r) {
			writeJSON(w, http.StatusForbidden, apiResponse{Error: "HTTPS is required for this sensitive action"})
			return
		}
		token, ok := s.currentSessionToken(r)
		if !ok || !s.sessionStore.RecentlyReauthenticated(token) {
			if isWebSocketUpgrade(r) {
				// #region agent log
				agentDebugLog("B", "session_security.go:reauthMiddleware", "ws upgrade rejected reauth required", map[string]interface{}{
					"host": r.Host, "hasToken": ok, "requireSecure": requireSecure,
				})
				// #endregion
				recordTerminalWSReject(http.StatusForbidden, "recent reauthentication required")
				http.Error(w, "recent reauthentication required", http.StatusForbidden)
				return
			}
			writeJSON(w, http.StatusForbidden, apiResponse{Error: "recent reauthentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (s *Server) requireReauth(next http.Handler) http.Handler {
	return s.authMiddleware(s.reauthMiddleware(next, false))
}

func (s *Server) requireSecureReauth(next http.Handler) http.Handler {
	return s.authMiddleware(s.reauthMiddleware(next, true))
}

func requestIsSecureEnough(r *http.Request) bool {
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "" {
		return proto == "https"
	}
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return isLoopback(host)
}
