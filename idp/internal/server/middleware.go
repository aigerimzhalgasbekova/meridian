package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// noStore marks token-bearing responses uncacheable (RFC 6749 §5.1).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// maxBody caps every request body. The form endpoints (/token, /login,
// /consent, /device, /introspect, /revoke) call r.ParseForm, which otherwise
// reads the body into memory with no bound — an unauthenticated memory-
// exhaustion DoS. Wrapping r.Body once here makes ParseForm and every JSON
// decoder fail closed past the cap (handlers already surface that as 400).
// 1 MiB matches the platform's other services; the register endpoint keeps
// its own tighter 64 KiB inner cap.
const maxBody = 1 << 20

func withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func withRequestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var idBytes [8]byte
		_, _ = rand.Read(idBytes[:])
		reqID := hex.EncodeToString(idBytes[:])
		w.Header().Set("X-Request-Id", reqID)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if p := recover(); p != nil {
				logger.Error("panic", "request_id", reqID, "path", r.URL.Path, "panic", p)
				writeJSON(rec, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			}
			// URL query is deliberately not logged: authorize requests
			// carry state/nonce/code_challenge, and callbacks carry codes.
			logger.Info("http",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()
		next.ServeHTTP(rec, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY") // login/consent pages must never be framed
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// remoteIP extracts the client IP the brute-force guard keys on.
//
// X-Forwarded-For is attacker-controlled unless a proxy we trust rewrites it,
// so it is consulted only when the operator asserts that topology
// (Config.TrustProxyHeaders). Even then only the LAST hop is read: a proxy
// that appends the peer address it observed — as an AWS ALB does — cannot be
// made to forge that final entry, while everything to its left was supplied by
// the client. Reading the first hop, the common mistake, would hand every
// attacker a fresh lockout bucket per request.
func remoteIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.LastIndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[i+1:])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
