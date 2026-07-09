package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type ctxKey int

const requestIDKey ctxKey = 0

// apiError is the uniform error envelope.
type apiError struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, apiError{Error: code, Detail: detail})
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// withObservability adds request ID, structured logging, and panic recovery.
func withObservability(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var idBytes [8]byte
		_, _ = rand.Read(idBytes[:])
		reqID := hex.EncodeToString(idBytes[:])
		w.Header().Set("X-Request-Id", reqID)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if p := recover(); p != nil {
				logger.Error("panic", "request_id", reqID, "panic", p)
				writeError(rec, http.StatusInternalServerError, "internal", "")
			}
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

// bearerAuth returns middleware requiring one of the given tokens.
// Comparison hashes both sides first so length is not observable, then uses a
// constant-time comparison.
func bearerAuth(tokens ...string) func(http.Handler) http.Handler {
	hashes := make([][32]byte, 0, len(tokens))
	for _, tok := range tokens {
		if tok != "" {
			hashes = append(hashes, sha256.Sum256([]byte(tok)))
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(hashes) == 0 {
				writeError(w, http.StatusServiceUnavailable, "auth_unconfigured",
					"no API token configured for this endpoint class")
				return
			}
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || raw == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="keysmith"`)
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
				return
			}
			got := sha256.Sum256([]byte(raw))
			authorized := false
			for _, want := range hashes {
				if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
					authorized = true
					// No break: uniform work regardless of match position.
				}
			}
			if !authorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="keysmith", error="invalid_token"`)
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid bearer token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
