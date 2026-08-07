package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/console/internal/auth"
	"github.com/aikazzh/portfolio/console/rbac"
)

var testKey = []byte("test-key")

// fixture: root (super-admin, global), olivia (operator, global),
// alice (realm-admin, engineering), vera (viewer, global).
func newTestServer(t *testing.T) (*Server, *MemStore) {
	t.Helper()
	e := rbac.New()
	for _, a := range []rbac.Assignment{
		{Subject: "root", Role: rbac.RoleSuperAdmin},
		{Subject: "olivia", Role: rbac.RoleOperator},
		{Subject: "alice", Role: rbac.RoleRealmAdmin, Scope: rbac.Scope{Realm: "engineering"}},
		{Subject: "vera", Role: rbac.RoleViewer},
		{Subject: "carol", Role: rbac.RoleRealmAdmin, Scope: rbac.Scope{Realm: "finance"}},
	} {
		if err := e.Assign(a); err != nil {
			t.Fatal(err)
		}
	}
	store := NewMemStore()
	store.AddUser(User{ID: "u-eng", Email: "eng@example.com", Realm: "engineering"})
	store.AddUser(User{ID: "u-fin", Email: "fin@example.com", Realm: "finance"})
	store.AddSession(Session{ID: "sess-eng", UserID: "u-eng", CreatedAt: time.Unix(1e9, 0)})
	store.AddSession(Session{ID: "sess-fin", UserID: "u-fin", CreatedAt: time.Unix(1e9, 0)})
	return New(Config{
		Engine:   e,
		Verifier: auth.HS256{Key: testKey},
		Users:    store,
		Sessions: store,
	}), store
}

func token(t *testing.T, subject string) string {
	t.Helper()
	return auth.HS256{Key: testKey}.Mint(subject, time.Hour)
}

// do performs a request as subject ("" = no token) and decodes the JSON body.
func do(t *testing.T, s *Server, subject, method, path, body string, out any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if subject != "" {
		req.Header.Set("Authorization", "Bearer "+token(t, subject))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if out != nil && w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s %s response: %v\n%s", method, path, err, w.Body.String())
		}
	}
	return w
}

func TestAuthn(t *testing.T) {
	s, _ := newTestServer(t)
	if w := do(t, s, "", "GET", "/v1/roles", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", w.Code)
	}
	req := httptest.NewRequest("GET", "/v1/roles", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: got %d, want 401", w.Code)
	}
	if w := do(t, s, "", "GET", "/healthz", "", nil); w.Code != http.StatusOK {
		t.Errorf("healthz: got %d, want 200", w.Code)
	}
}

func TestRoleCRUDAuthz(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"name":"auditor","grants":["audit:read"]}`

	t.Run("operator cannot create roles", func(t *testing.T) {
		var e apiError
		w := do(t, s, "olivia", "POST", "/v1/roles", body, &e)
		if w.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403: %s", w.Code, w.Body)
		}
		if e.Decision == nil || e.Decision.Allowed {
			t.Error("403 body must carry the deny decision trace")
		}
	})
	t.Run("realm-admin cannot create roles (global object)", func(t *testing.T) {
		if w := do(t, s, "alice", "POST", "/v1/roles", body, nil); w.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403: %s", w.Code, w.Body)
		}
	})
	t.Run("super-admin creates, updates, deletes", func(t *testing.T) {
		if w := do(t, s, "root", "POST", "/v1/roles", body, nil); w.Code != http.StatusCreated {
			t.Fatalf("create: got %d: %s", w.Code, w.Body)
		}
		if w := do(t, s, "root", "POST", "/v1/roles", body, nil); w.Code != http.StatusConflict {
			t.Fatalf("duplicate create: got %d, want 409", w.Code)
		}
		up := `{"name":"auditor","grants":["audit:read","sessions:read"]}`
		if w := do(t, s, "root", "PUT", "/v1/roles/auditor", up, nil); w.Code != http.StatusOK {
			t.Fatalf("update: got %d: %s", w.Code, w.Body)
		}
		var role rbac.Role
		do(t, s, "vera", "GET", "/v1/roles/auditor", "", &role)
		if len(role.Grants) != 2 {
			t.Errorf("update not applied: %+v", role)
		}
		if w := do(t, s, "root", "DELETE", "/v1/roles/auditor", "", nil); w.Code != http.StatusNoContent {
			t.Fatalf("delete: got %d: %s", w.Code, w.Body)
		}
		if w := do(t, s, "root", "DELETE", "/v1/roles/auditor", "", nil); w.Code != http.StatusNotFound {
			t.Fatalf("delete missing: got %d, want 404", w.Code)
		}
	})
	t.Run("builtins protected", func(t *testing.T) {
		if w := do(t, s, "root", "DELETE", "/v1/roles/viewer", "", nil); w.Code != http.StatusConflict {
			t.Errorf("delete builtin: got %d, want 409", w.Code)
		}
		if w := do(t, s, "root", "PUT", "/v1/roles/viewer", `{"grants":["*:*"]}`, nil); w.Code != http.StatusBadRequest {
			t.Errorf("update builtin: got %d, want 400", w.Code)
		}
	})
	t.Run("invalid role rejected", func(t *testing.T) {
		if w := do(t, s, "root", "POST", "/v1/roles", `{"name":"x","grants":["nope"]}`, nil); w.Code != http.StatusBadRequest {
			t.Errorf("bad grant: got %d, want 400", w.Code)
		}
	})
}

func TestAssignmentScopeEnforcement(t *testing.T) {
	s, _ := newTestServer(t)
	own := `{"subject":"newbie","role":"viewer","scope":{"realm":"engineering"}}`
	other := `{"subject":"newbie","role":"viewer","scope":{"realm":"finance"}}`
	global := `{"subject":"newbie","role":"viewer","scope":{}}`

	if w := do(t, s, "alice", "POST", "/v1/assignments", own, nil); w.Code != http.StatusCreated {
		t.Fatalf("realm-admin in own realm: got %d: %s", w.Code, w.Body)
	}
	if w := do(t, s, "alice", "POST", "/v1/assignments", other, nil); w.Code != http.StatusForbidden {
		t.Fatalf("realm-admin in other realm: got %d, want 403", w.Code)
	}
	if w := do(t, s, "alice", "POST", "/v1/assignments", global, nil); w.Code != http.StatusForbidden {
		t.Fatalf("realm-admin at global: got %d, want 403", w.Code)
	}
	if w := do(t, s, "alice", "POST", "/v1/assignments/revoke", own, nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke in own realm: got %d: %s", w.Code, w.Body)
	}
	if w := do(t, s, "alice", "POST", "/v1/assignments/revoke", own, nil); w.Code != http.StatusNotFound {
		t.Fatalf("revoke missing: got %d, want 404", w.Code)
	}
	if w := do(t, s, "root", "POST", "/v1/assignments", global, nil); w.Code != http.StatusCreated {
		t.Fatalf("super-admin global assign: got %d: %s", w.Code, w.Body)
	}
	if w := do(t, s, "root", "POST", "/v1/assignments", `{"subject":"x","role":"ghost"}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: got %d, want 400", w.Code)
	}
}

func TestExplain(t *testing.T) {
	s, _ := newTestServer(t)

	var d rbac.Decision
	w := do(t, s, "vera", "GET", "/v1/authz/explain?subject=alice&permission=users:write&realm=engineering", "", &d)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if !d.Allowed || d.Decider == nil || d.Decider.Role != rbac.RoleOperator {
		t.Errorf("explain: want allow decided by operator's grant, got %+v", d)
	}
	if len(d.Trace) == 0 {
		t.Error("explain must return the trace")
	}

	if w := do(t, s, "vera", "GET", "/v1/authz/explain?subject=alice&permission=users:*", "", nil); w.Code != http.StatusBadRequest {
		t.Errorf("wildcard query: got %d, want 400", w.Code)
	}
	if w := do(t, s, "vera", "GET", "/v1/authz/explain?permission=users:read", "", nil); w.Code != http.StatusBadRequest {
		t.Errorf("missing subject: got %d, want 400", w.Code)
	}

	// Realm confinement: alice holds authz:explain only in engineering, so
	// she must not read finance's authorization graph — the same rule
	// /v1/users and /v1/users/{id}/sessions enforce.
	if w := do(t, s, "alice", "GET", "/v1/authz/explain?subject=bob&permission=users:write&realm=engineering", "", nil); w.Code != http.StatusOK {
		t.Errorf("own-realm explain: got %d, want 200: %s", w.Code, w.Body)
	}
	if w := do(t, s, "alice", "GET", "/v1/authz/explain?subject=bob&permission=users:write&realm=finance", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("cross-realm explain: got %d, want 403: %s", w.Code, w.Body)
	}
	if w := do(t, s, "alice", "GET", "/v1/authz/explain?subject=bob&permission=users:write", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("global-scope explain by a realm-admin: got %d, want 403", w.Code)
	}

	// Scoping the authorization is not enough: the trace itself must not carry
	// assignments from realms the caller cannot read. carol is a finance
	// realm-admin, and alice — authorized at engineering — must not learn that.
	var cd rbac.Decision
	if w := do(t, s, "alice", "GET", "/v1/authz/explain?subject=carol&permission=users:write&realm=engineering", "", &cd); w.Code != http.StatusOK {
		t.Fatalf("explain: got %d, want 200: %s", w.Code, w.Body)
	}
	if cd.Allowed {
		t.Error("carol must not be allowed users:write in engineering")
	}
	for _, at := range cd.Trace {
		t.Errorf("explain leaked an out-of-scope assignment: %+v", at.Assignment)
	}
}

func TestUserLifecycleAndRealmFilter(t *testing.T) {
	s, _ := newTestServer(t)

	t.Run("realm-admin sees only own realm", func(t *testing.T) {
		var resp struct{ Users []User }
		do(t, s, "alice", "GET", "/v1/users", "", &resp)
		if len(resp.Users) != 1 || resp.Users[0].ID != "u-eng" {
			t.Errorf("alice sees %+v, want only u-eng", resp.Users)
		}
	})
	t.Run("global viewer sees all", func(t *testing.T) {
		var resp struct{ Users []User }
		do(t, s, "vera", "GET", "/v1/users", "", &resp)
		if len(resp.Users) != 2 {
			t.Errorf("vera sees %d users, want 2", len(resp.Users))
		}
	})
	t.Run("realm-admin disables own-realm user", func(t *testing.T) {
		var u User
		if w := do(t, s, "alice", "POST", "/v1/users/u-eng/disable", "", &u); w.Code != http.StatusOK || !u.Disabled {
			t.Fatalf("got %d %+v", w.Code, u)
		}
		if w := do(t, s, "alice", "POST", "/v1/users/u-eng/enable", "", &u); w.Code != http.StatusOK || u.Disabled {
			t.Fatalf("enable: got %d %+v", w.Code, u)
		}
	})
	t.Run("realm-admin cannot touch other realm", func(t *testing.T) {
		if w := do(t, s, "alice", "POST", "/v1/users/u-fin/disable", "", nil); w.Code != http.StatusForbidden {
			t.Errorf("got %d, want 403", w.Code)
		}
	})
	t.Run("viewer cannot disable", func(t *testing.T) {
		if w := do(t, s, "vera", "POST", "/v1/users/u-eng/disable", "", nil); w.Code != http.StatusForbidden {
			t.Errorf("got %d, want 403", w.Code)
		}
	})
	if w := do(t, s, "root", "POST", "/v1/users/ghost/disable", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("missing user: got %d, want 404", w.Code)
	}
}

func TestSessions(t *testing.T) {
	s, store := newTestServer(t)

	var resp struct{ Sessions []Session }
	if w := do(t, s, "alice", "GET", "/v1/users/u-eng/sessions", "", &resp); w.Code != http.StatusOK || len(resp.Sessions) != 1 {
		t.Fatalf("list own-realm sessions: %d %+v", w.Code, resp)
	}
	if w := do(t, s, "alice", "GET", "/v1/users/u-fin/sessions", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("other-realm sessions: got %d, want 403", w.Code)
	}
	if w := do(t, s, "alice", "POST", "/v1/sessions/sess-fin/revoke", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("other-realm revoke: got %d, want 403", w.Code)
	}
	if w := do(t, s, "olivia", "POST", "/v1/sessions/sess-eng/revoke", "", nil); w.Code != http.StatusNoContent {
		t.Errorf("operator revoke: got %d, want 204", w.Code)
	}
	if _, ok, _ := store.Session(context.Background(), "sess-eng"); ok {
		t.Error("session not actually revoked")
	}
	if w := do(t, s, "olivia", "POST", "/v1/sessions/ghost/revoke", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("missing session: got %d, want 404", w.Code)
	}
}

func TestAuditTrail(t *testing.T) {
	s, _ := newTestServer(t)
	// One allowed and one denied mutation, both must land in the trail.
	do(t, s, "root", "POST", "/v1/roles", `{"name":"tmp","grants":["audit:read"]}`, nil)
	do(t, s, "olivia", "POST", "/v1/roles", `{"name":"nope","grants":["audit:read"]}`, nil)

	var resp struct{ Events []AuditEvent }
	if w := do(t, s, "root", "GET", "/v1/audit", "", &resp); w.Code != http.StatusOK {
		t.Fatalf("audit read: %d", w.Code)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("got %d audit events, want 2: %+v", len(resp.Events), resp.Events)
	}
	// Newest first: the denied attempt.
	if resp.Events[0].Actor != "olivia" || resp.Events[0].Allowed {
		t.Errorf("denied mutation not audited: %+v", resp.Events[0])
	}
	if resp.Events[1].Actor != "root" || !resp.Events[1].Allowed {
		t.Errorf("allowed mutation not audited: %+v", resp.Events[1])
	}
	// audit:read is global-only: realm-admin alice holds it only in her realm.
	if w := do(t, s, "alice", "GET", "/v1/audit", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("realm-admin reading global audit: got %d, want 403", w.Code)
	}
}

func TestCatalogEndpoints(t *testing.T) {
	s, _ := newTestServer(t)
	var perms struct{ Permissions []rbac.Permission }
	if w := do(t, s, "vera", "GET", "/v1/permissions", "", &perms); w.Code != http.StatusOK || len(perms.Permissions) == 0 {
		t.Errorf("permissions: %d %+v", w.Code, perms)
	}
	var roles struct{ Roles []rbac.Role }
	if w := do(t, s, "alice", "GET", "/v1/roles", "", &roles); w.Code != http.StatusOK || len(roles.Roles) != 4 {
		t.Errorf("realm-admin must read the role catalog: %d, %d roles", w.Code, len(roles.Roles))
	}
	var one rbac.Role
	if w := do(t, s, "vera", "GET", "/v1/roles/operator", "", &one); w.Code != http.StatusOK || one.Extends != rbac.RoleViewer {
		t.Errorf("get role: %d %+v", w.Code, one)
	}
	if w := do(t, s, "vera", "GET", "/v1/roles/ghost", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("missing role: got %d, want 404", w.Code)
	}
}
