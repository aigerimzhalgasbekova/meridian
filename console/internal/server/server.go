// Package server implements the console control-plane API.
//
// Route map (all /v1 routes require a bearer token; the permission each
// route demands, and at what scope, is listed):
//
//	GET    /healthz                       liveness (unauthenticated)
//	GET    /v1/permissions                permissions:read  (any held scope)
//	GET    /v1/roles                      roles:read        (any held scope)
//	GET    /v1/roles/{name}               roles:read        (any held scope)
//	POST   /v1/roles                      roles:write       (global)
//	PUT    /v1/roles/{name}               roles:write       (global)
//	DELETE /v1/roles/{name}               roles:write       (global)
//	GET    /v1/assignments                assignments:read  (any held scope)
//	POST   /v1/assignments                assignments:write (at the assignment's scope)
//	POST   /v1/assignments/revoke         assignments:write (at the assignment's scope)
//	GET    /v1/authz/explain              authz:explain     (any held scope)
//	GET    /v1/users                      users:read        (list filtered to readable realms)
//	POST   /v1/users/{id}/disable         users:write       (target user's realm)
//	POST   /v1/users/{id}/enable          users:write       (target user's realm)
//	GET    /v1/users/{id}/sessions        sessions:read     (target user's realm)
//	POST   /v1/sessions/{id}/revoke       sessions:revoke   (session owner's realm)
//	GET    /v1/audit                      audit:read        (global)
//
// The console eats its own dog food: every route is gated by the same rbac
// engine it administers, and the 403 body is the engine's full explanation
// trace — a denied admin sees exactly why. Role definitions are global
// objects, so writing them demands global scope (a realm-admin cannot mint
// roles). Assignment writes are checked at the scope being granted, which
// is what confines a realm-admin to their realm.
//
// Errors use one envelope: {"error": "<code>", "message": "..."} (plus
// "decision" on authorization denials).
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aikazzh/portfolio/console/internal/auth"
	"github.com/aikazzh/portfolio/console/rbac"
)

// Config assembles a Server.
type Config struct {
	Engine   *rbac.Engine
	Verifier auth.Verifier
	Users    UserStore
	Sessions SessionProvider
	Audit    *AuditLog
	Logger   *slog.Logger
	Now      func() time.Time
	// DevTokens, when non-empty, enables GET /v1/dev/tokens returning
	// pre-minted persona tokens. Local demo only; never set in production.
	DevTokens map[string]string
}

// Server is the console HTTP server.
type Server struct {
	cfg     Config
	handler http.Handler
}

// New wires routes and middleware.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audit == nil {
		cfg.Audit = &AuditLog{}
	}
	s := &Server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if len(cfg.DevTokens) > 0 {
		mux.HandleFunc("GET /v1/dev/tokens", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, cfg.DevTokens)
		})
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /v1/permissions", s.listPermissions)
	api.HandleFunc("GET /v1/roles", s.listRoles)
	api.HandleFunc("GET /v1/roles/{name}", s.getRole)
	api.HandleFunc("POST /v1/roles", s.createRole)
	api.HandleFunc("PUT /v1/roles/{name}", s.updateRole)
	api.HandleFunc("DELETE /v1/roles/{name}", s.deleteRole)
	api.HandleFunc("GET /v1/assignments", s.listAssignments)
	api.HandleFunc("POST /v1/assignments", s.createAssignment)
	api.HandleFunc("POST /v1/assignments/revoke", s.revokeAssignment)
	api.HandleFunc("GET /v1/authz/explain", s.explain)
	api.HandleFunc("GET /v1/users", s.listUsers)
	api.HandleFunc("POST /v1/users/{id}/disable", s.setUserDisabled(true))
	api.HandleFunc("POST /v1/users/{id}/enable", s.setUserDisabled(false))
	api.HandleFunc("GET /v1/users/{id}/sessions", s.listSessions)
	api.HandleFunc("POST /v1/sessions/{id}/revoke", s.revokeSession)
	api.HandleFunc("GET /v1/audit", s.listAudit)
	mux.Handle("/v1/", s.withAuth(api))

	s.handler = withRequestLog(cfg.Logger, withSecurityHeaders(mux))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// --- error envelope ---

type apiError struct {
	Error    string         `json:"error"`
	Message  string         `json:"message,omitempty"`
	Decision *rbac.Decision `json:"decision,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}

// --- authn middleware ---

type ctxKey int

const subjectKey ctxKey = 0

func subject(r *http.Request) string {
	sub, _ := r.Context().Value(subjectKey).(string)
	return sub
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="console"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "bearer token required")
			return
		}
		sub, err := s.cfg.Verifier.Verify(strings.TrimPrefix(h, prefix))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey, sub)))
	})
}

// --- authz helpers ---

// require checks perm at scope for the caller. On denial it writes a 403
// carrying the engine's full explanation and returns false.
func (s *Server) require(w http.ResponseWriter, r *http.Request, perm rbac.Permission, scope rbac.Scope) bool {
	d := s.cfg.Engine.Check(subject(r), perm, scope)
	if !d.Allowed {
		writeJSON(w, http.StatusForbidden, apiError{
			Error:    "forbidden",
			Message:  string(perm) + " denied at scope " + scope.String(),
			Decision: &d,
		})
		return false
	}
	return true
}

// requireAnywhere is require for global catalog reads (roles, permissions,
// the explain endpoint): the caller passes if the permission holds at
// global scope or within any realm they hold an assignment in. A
// realm-admin must be able to read the role catalog to assign from it.
func (s *Server) requireAnywhere(w http.ResponseWriter, r *http.Request, perm rbac.Permission) bool {
	sub := subject(r)
	d := s.cfg.Engine.Check(sub, perm, rbac.Global)
	if !d.Allowed {
		for _, a := range s.cfg.Engine.Assignments(sub) {
			if !a.Scope.IsGlobal() {
				if rd := s.cfg.Engine.Check(sub, perm, a.Scope); rd.Allowed {
					return true
				}
			}
		}
		writeJSON(w, http.StatusForbidden, apiError{
			Error:    "forbidden",
			Message:  string(perm) + " denied in every scope you hold",
			Decision: &d,
		})
		return false
	}
	return true
}

// audit records a mutating call and its authorization outcome.
func (s *Server) audit(r *http.Request, action, target string, scope rbac.Scope, allowed bool, detail string) {
	s.cfg.Audit.Append(AuditEvent{
		Time:    s.cfg.Now().UTC(),
		Actor:   subject(r),
		Action:  action,
		Target:  target,
		Scope:   scope.String(),
		Allowed: allowed,
		Detail:  detail,
	})
}

// requireAudited is require for mutations: the decision is appended to the
// audit trail whether it passed or not.
func (s *Server) requireAudited(w http.ResponseWriter, r *http.Request, perm rbac.Permission, scope rbac.Scope, action, target string) bool {
	d := s.cfg.Engine.Check(subject(r), perm, scope)
	s.audit(r, action, target, scope, d.Allowed, "")
	if !d.Allowed {
		writeJSON(w, http.StatusForbidden, apiError{
			Error:    "forbidden",
			Message:  string(perm) + " denied at scope " + scope.String(),
			Decision: &d,
		})
		return false
	}
	return true
}

// --- logging / headers middleware ---

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
				writeError(rec, http.StatusInternalServerError, "server_error", "")
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

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
