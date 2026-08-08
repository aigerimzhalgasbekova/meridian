package server

import (
	"encoding/json"
	"fmt"
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

// detail summarizes a role write for the audit trail: a role.update event
// with no content cannot reveal the escalation it carried (someone adding
// "*:*" to a widely-held role).
func (b roleBody) detail() string {
	return fmt.Sprintf("extends=%q grants=%v denies=%v", b.Extends, b.Grants, b.Denies)
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
	s.audit(r, "role.create", b.Name, rbac.Global, true, b.detail())
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
	s.audit(r, "role.update", name, rbac.Global, true, b.detail())
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
	s.audit(r, "role.delete", name, rbac.Global, true, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- assignments ---

// listAssignments returns the assignments the caller may read. An assignment
// is the one object in the model that is intrinsically realm-partitioned, so
// the catalog-read gate is not enough on its own: the list is filtered to the
// scopes the caller actually holds assignments:read in, the same rule
// /v1/users and /v1/authz/explain enforce.
//
// ponytail: one Check per assignment, like listUsers. Memoize by scope if the
// assignment table ever gets big enough for the repeated walks to show up.
func (s *Server) listAssignments(w http.ResponseWriter, r *http.Request) {
	if !s.requireAnywhere(w, r, "assignments:read") {
		return
	}
	sub := subject(r)
	all := s.cfg.Engine.Assignments(r.URL.Query().Get("subject"))
	out := make([]rbac.Assignment, 0, len(all))
	for _, a := range all {
		if s.cfg.Engine.Check(sub, "assignments:read", a.Scope).Allowed {
			out = append(out, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": out})
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
	s.audit(r, "assignment.create", a.Subject+"→"+a.Role, a.Scope, true, "")
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
	s.audit(r, "assignment.revoke", a.Subject+"→"+a.Role, a.Scope, true, "")
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
			// The realm-derived scope forces a lookup before the check, so a
			// bare 404 would be a cross-realm existence oracle. Answer 404
			// only to a caller authorized for *any* target — the miss tells
			// them nothing they could not already have learned. Everyone else
			// gets the target-blind 403, and the probe is audited.
			if !s.requireAnyTarget(w, r, "users:write", action, id) {
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		// Authorized at the target user's realm: an engineering realm-admin
		// cannot disable a finance user.
		scope := rbac.Scope{Realm: u.Realm}
		if !s.requireTarget(w, r, "users:write", scope, action, id) {
			return
		}
		u, changed, err := s.cfg.Users.SetDisabled(r.Context(), id, disabled)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "user store unavailable")
			return
		}
		// The user can vanish between the lookup above and this write — an
		// ordinary race once users live in Postgres. Nothing changed, so there
		// is no success to audit and no user to return.
		if !changed {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		s.audit(r, action, id, scope, true, "")
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
		// Same existence-oracle guard as setUserDisabled.
		if !s.requireAnyTarget(w, r, "sessions:read", "", "") {
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if !s.requireTarget(w, r, "sessions:read", rbac.Scope{Realm: u.Realm}, "", "") {
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
		// Same existence-oracle guard as setUserDisabled.
		if !s.requireAnyTarget(w, r, "sessions:revoke", "session.revoke", id) {
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	u, uok, err := s.cfg.Users.User(r.Context(), sess.UserID)
	if err != nil {
		// The user store being down is exactly when an operator most needs
		// this endpoint (killing a hijacked session mid-incident). Treat the
		// owner as unresolvable and fall through to the global-scope check
		// below — the strictest allow — rather than refusing to revoke at all.
		uok = false
	}
	// Scope is the session owner's realm. A session outliving its owner is the
	// ordinary state right after a user deletion — exactly when an operator
	// most needs the revoke — but it has no realm, so the check can only fall
	// back to global. Global is the strictest scope for allows and the weakest
	// for denies: a realm-scoped deny carve-out does not cover a global query,
	// so only a caller allowed for every target may be checked there.
	scope := rbac.Scope{Realm: u.Realm}
	if !uok {
		scope = rbac.Global
		if !s.requireAnyTarget(w, r, "sessions:revoke", "session.revoke", id) {
			return
		}
	} else if !s.requireTarget(w, r, "sessions:revoke", scope, "session.revoke", id) {
		return
	}
	revoked, err := s.cfg.Sessions.RevokeSession(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "session backend unavailable")
		return
	}
	// The session can vanish between the lookup above and this write — an
	// ordinary race once sessions live in sessiond/Redis. Nothing changed, so
	// there is no success to audit.
	if !revoked {
		writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	s.audit(r, "session.revoke", id, scope, true, "")
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
