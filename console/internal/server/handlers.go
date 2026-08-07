package server

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/aikazzh/portfolio/console/rbac"
)

// Catalog is the set of concrete permissions the console itself understands
// and gates on. Custom roles may reference these (or wildcards over them).
var Catalog = []rbac.Permission{
	"users:read", "users:write",
	"roles:read", "roles:write",
	"assignments:read", "assignments:write",
	"sessions:read", "sessions:revoke",
	"audit:read", "permissions:read", "authz:explain",
}

// decode reads a JSON body into v with a size cap.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// --- permissions / roles ---

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "permissions:read") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": Catalog})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "roles:read") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": s.cfg.Engine.Roles()})
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "roles:read") {
		return
	}
	role, ok := s.cfg.Engine.Role(r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "role not found")
		return
	}
	writeJSON(w, http.StatusOK, role)
}

// roleBody is the create/update payload; Builtin is not client-settable.
type roleBody struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Extends     string            `json:"extends"`
	Grants      []rbac.Permission `json:"grants"`
	Denies      []rbac.Permission `json:"denies"`
}

func (b roleBody) role() rbac.Role {
	return rbac.Role{Name: b.Name, Description: b.Description, Extends: b.Extends, Grants: b.Grants, Denies: b.Denies}
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var b roleBody
	if !decode(w, r, &b) {
		return
	}
	// Role definitions are global objects: writing them demands global scope.
	if !s.requireAudited(w, r, "roles:write", rbac.Global, "role.create", b.Name) {
		return
	}
	if _, exists := s.cfg.Engine.Role(b.Name); exists {
		writeError(w, http.StatusConflict, "conflict", "role already exists; use PUT to update")
		return
	}
	if err := s.cfg.Engine.DefineRole(b.role()); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	role, _ := s.cfg.Engine.Role(b.Name)
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var b roleBody
	if !decode(w, r, &b) {
		return
	}
	if b.Name != "" && b.Name != name {
		writeError(w, http.StatusBadRequest, "bad_request", "body name must match path")
		return
	}
	b.Name = name
	if !s.requireAudited(w, r, "roles:write", rbac.Global, "role.update", name) {
		return
	}
	if _, exists := s.cfg.Engine.Role(name); !exists {
		writeError(w, http.StatusNotFound, "not_found", "role not found")
		return
	}
	if err := s.cfg.Engine.DefineRole(b.role()); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	role, _ := s.cfg.Engine.Role(name)
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.requireAudited(w, r, "roles:write", rbac.Global, "role.delete", name) {
		return
	}
	if err := s.cfg.Engine.DeleteRole(name); err != nil {
		if _, exists := s.cfg.Engine.Role(name); !exists {
			writeError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- assignments ---

func (s *Server) listAssignments(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "assignments:read") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"assignments": s.cfg.Engine.Assignments(r.URL.Query().Get("subject")),
	})
}

// Assignment writes are authorized at the scope being granted or revoked —
// this single check is what confines a realm-admin to their own realm.
func (s *Server) createAssignment(w http.ResponseWriter, r *http.Request) {
	var a rbac.Assignment
	if !decode(w, r, &a) {
		return
	}
	if !s.requireAudited(w, r, "assignments:write", a.Scope, "assignment.create", a.Subject+"→"+a.Role) {
		return
	}
	if err := s.cfg.Engine.Assign(a); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) revokeAssignment(w http.ResponseWriter, r *http.Request) {
	var a rbac.Assignment
	if !decode(w, r, &a) {
		return
	}
	if !s.requireAudited(w, r, "assignments:write", a.Scope, "assignment.revoke", a.Subject+"→"+a.Role) {
		return
	}
	if !s.cfg.Engine.Revoke(a) {
		writeError(w, http.StatusNotFound, "not_found", "assignment not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- explain ---

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sub := q.Get("subject")
	perm := rbac.Permission(q.Get("permission"))
	scope := rbac.Scope{Realm: q.Get("realm")}
	// Authorized at the *queried* scope, like every other realm-sensitive
	// route: an engineering realm-admin must not read finance's authorization
	// graph, and only a global holder may explain at global scope.
	if !s.require(w, r, "authz:explain", scope) {
		return
	}
	if sub == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "subject is required")
		return
	}
	if err := perm.ValidateConcrete(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	d := s.cfg.Engine.Check(sub, perm, scope)
	// Scoping the *authorization* is not enough: Check traces every assignment
	// the subject holds, so a realm-scoped caller would still read another
	// realm's subject→role graph (and learn whether a subject exists at all).
	// A non-matching assignment decided nothing here — its Chain is empty —
	// so dropping it costs the answer nothing.
	d.Trace = slices.DeleteFunc(d.Trace, func(at rbac.AssignmentTrace) bool { return !at.ScopeMatch })
	writeJSON(w, http.StatusOK, d)
}

// --- users ---

// listUsers returns the users the caller may read: everyone with a global
// users:read, otherwise only users in realms where the caller holds it.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "users:read") {
		return
	}
	users, err := s.cfg.Users.Users(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "user store unavailable")
		return
	}
	sub := subject(r)
	out := make([]User, 0, len(users))
	for _, u := range users {
		if s.cfg.Engine.Check(sub, "users:read", rbac.Scope{Realm: u.Realm}).Allowed {
			out = append(out, u)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) setUserDisabled(disabled bool) http.HandlerFunc {
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		u, ok, err := s.cfg.Users.User(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "user store unavailable")
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		// Authorized at the target user's realm: an engineering realm-admin
		// cannot disable a finance user.
		if !s.requireAudited(w, r, "users:write", rbac.Scope{Realm: u.Realm}, action, id) {
			return
		}
		u, _, err = s.cfg.Users.SetDisabled(r.Context(), id, disabled)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "user store unavailable")
			return
		}
		writeJSON(w, http.StatusOK, u)
	}
}

// --- sessions ---

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, ok, err := s.cfg.Users.User(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "user store unavailable")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if !s.require(w, r, "sessions:read", rbac.Scope{Realm: u.Realm}) {
		return
	}
	sessions, err := s.cfg.Sessions.Sessions(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "session backend unavailable")
		return
	}
	if sessions == nil {
		sessions = []Session{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok, err := s.cfg.Sessions.Session(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "session backend unavailable")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	// Scope is the session owner's realm.
	scope := rbac.Global
	if u, uok, _ := s.cfg.Users.User(r.Context(), sess.UserID); uok {
		scope = rbac.Scope{Realm: u.Realm}
	}
	if !s.requireAudited(w, r, "sessions:revoke", scope, "session.revoke", id) {
		return
	}
	if _, err := s.cfg.Sessions.RevokeSession(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "session backend unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, "audit:read", rbac.Global) {
		return
	}
	events := s.cfg.Audit.Events()
	if events == nil {
		events = []AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
