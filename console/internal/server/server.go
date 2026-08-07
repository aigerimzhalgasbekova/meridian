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
//	GET    /v1/assignments                assignments:read  (list filtered to readable scopes)
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
// trace — a denied admin sees exactly why. The exception is the three routes
// addressed by a target id (user disable/enable, user sessions, session
// revoke): their denial names neither scope nor decision, because the scope is
// the target's realm and would leak whether the target exists (requireTarget).
// Role definitions are global
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

	s.handler = withRequestLog(cfg.Logger, WithSecurityHeaders(mux))
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
		// The attached decision must explain the verdict it accompanies. The
		// global check marks every realm assignment scope-mismatched, so it
		// can never name a realm-scoped deny — keep an explicit deny from the
		// per-realm checks instead, and fall back to the global default_deny
		// only when no scope produced one.
		best := d
		for _, a := range s.cfg.Engine.Assignments(sub) {
			if a.Scope.IsGlobal() {
				continue
			}
			rd := s.cfg.Engine.Check(sub, perm, a.Scope)
			if rd.Allowed {
				return true
			}
			if best.Effect != rbac.EffectDeny && rd.Effect == rbac.EffectDeny {
				best = rd
			}
		}
		writeJSON(w, http.StatusForbidden, apiError{
			Error:    "forbidden",
			Message:  string(perm) + " denied in every scope you hold",
			Decision: &best,
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

// requireAudited is require for mutations. It appends the denial itself —
// nothing happened, so that event is complete by definition. The success
// event is the handler's job, appended after the mutation actually lands, so
// allowed:true in the trail means the change took effect rather than merely
// "was authorized".
func (s *Server) requireAudited(w http.ResponseWriter, r *http.Request, perm rbac.Permission, scope rbac.Scope, action, target string) bool {
	d := s.cfg.Engine.Check(subject(r), perm, scope)
	if !d.Allowed {
		s.audit(r, action, target, scope, false, "")
		writeJSON(w, http.StatusForbidden, apiError{
			Error:    "forbidden",
			Message:  string(perm) + " denied at scope " + scope.String(),
			Decision: &d,
		})
		return false
	}
	return true
}

// requireTarget gates the three routes addressed by a target id whose realm is
// only knowable after a store lookup (users/{id}/disable|enable,
// users/{id}/sessions, sessions/{id}/revoke). Their miss branch checks at
// global while a hit checks at the target's realm, so a denial envelope that
// names the scope — in the message or in the attached decision — is exactly the
// cross-realm existence oracle the bare 404 was. Both branches emit one fixed
// body instead, byte-identical for a miss and a cross-realm hit.
//
// This is the only place the console gives up its explanation trace, and it
// buys the property the 403 was introduced for; every other route keeps it.
// action == "" skips the audit — a read is not a mutation.
func (s *Server) requireTarget(w http.ResponseWriter, r *http.Request, perm rbac.Permission, scope rbac.Scope, action, target string) bool {
	if s.cfg.Engine.Check(subject(r), perm, scope).Allowed {
		return true
	}
	if action != "" {
		s.audit(r, action, target, scope, false, "")
	}
	writeError(w, http.StatusForbidden, "forbidden", string(perm)+" denied for this target")
	return false
}

// --- logging / headers middleware ---

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool // the response is committed; the client already saw status
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wrote {
		return // net/http would drop it anyway (and log "superfluous")
	}
	r.wrote, r.status = true, code
	r.ResponseWriter.WriteHeader(code)
}

// Write marks the response committed too: a handler that writes a body without
// calling WriteHeader flushes net/http's implicit 200, and the recover path
// must not append an error envelope to that either.
func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
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
				// Only answer when nothing was committed: appending an error
				// envelope to an already-flushed body corrupts it, and the
				// client keeps the status it already received either way.
				if !rec.wrote {
					writeError(rec, http.StatusInternalServerError, "server_error", "")
				}
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

// WithSecurityHeaders sets the console's response headers. It is exported
// because the SPA is served alongside the API by a wrapper that never routes
// static files through this server: index.html is the document the browser
// derives its CSP from, so the composed handler must be wrapped too (see
// cmd/consoled). Applying it twice is harmless — every header is Set.
//
// The CSP is the defence-in-depth layer behind React's escaping: the admin
// bearer token lives in localStorage, so any script execution on this origin
// exfiltrates the platform's highest-value credential.
//
// ponytail: Cache-Control: no-store applies to hashed static assets too. An
// internal admin tool can pay the reload; scope the header to /v1 if it ever
// serves enough traffic to notice.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; "+
			"style-src 'self'; connect-src 'self'; img-src 'self' data:; "+
			"object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
