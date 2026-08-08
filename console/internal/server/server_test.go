package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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
	return newTestServerUsers(t, nil)
}

// newTestServerUsers builds the fixture with the user store wrapped, so a test
// can model a store that behaves differently from MemStore. wrap == nil uses
// the MemStore directly.
func newTestServerUsers(t *testing.T, wrap func(*MemStore) UserStore) (*Server, *MemStore) {
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
	var users UserStore = store
	if wrap != nil {
		users = wrap(store)
	}
	return New(Config{
		Engine:   e,
		Verifier: auth.HS256{Key: testKey},
		Users:    users,
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

// An assignment is realm-partitioned data, not a global catalog object: the
// list must be filtered to the scopes the caller can read, or any realm-scoped
// viewer reads the platform-wide privilege map.
func TestListAssignmentsScopeFilter(t *testing.T) {
	s, _ := newTestServer(t)

	var resp struct{ Assignments []rbac.Assignment }
	if w := do(t, s, "alice", "GET", "/v1/assignments", "", &resp); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	for _, a := range resp.Assignments {
		if a.Scope != (rbac.Scope{Realm: "engineering"}) {
			t.Errorf("realm-admin read an assignment outside her realm: %+v", a)
		}
	}
	if len(resp.Assignments) != 1 {
		t.Errorf("alice must still see her own realm: %+v", resp.Assignments)
	}

	var all struct{ Assignments []rbac.Assignment }
	do(t, s, "vera", "GET", "/v1/assignments", "", &all)
	if len(all.Assignments) != 5 {
		t.Errorf("global viewer sees %d assignments, want all 5", len(all.Assignments))
	}
}

// The decision attached to a requireAnywhere 403 must explain that 403. The
// global check marks every realm assignment scope-mismatched, so attaching it
// would report an explicit realm deny as a default_deny with no decider.
func TestRequireAnywhereDenyCarriesTheDeny(t *testing.T) {
	s, _ := newTestServer(t)
	if w := do(t, s, "root", "POST", "/v1/roles",
		`{"name":"restricted","extends":"viewer","denies":["users:read"]}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("create role: got %d: %s", w.Code, w.Body)
	}
	if w := do(t, s, "root", "POST", "/v1/assignments",
		`{"subject":"alice","role":"restricted","scope":{"realm":"engineering"}}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("assign: got %d: %s", w.Code, w.Body)
	}

	var e apiError
	w := do(t, s, "alice", "GET", "/v1/users", "", &e)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body)
	}
	if e.Decision == nil || e.Decision.Effect != rbac.EffectDeny || e.Decision.Decider == nil {
		t.Fatalf("403 must carry the deny that caused it, got %+v", e.Decision)
	}
	if e.Decision.Decider.Role != "restricted" || e.Decision.Decider.Rule != "users:read" {
		t.Errorf("decider must name the deny rule, got %+v", e.Decision.Decider)
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

// vanishingStore models the ordinary race once users live in Postgres: the
// pre-authorization lookup finds the user, the write does not. The handler must
// not answer 200 with a zero-valued user, and must not append an allowed:true
// audit event for a mutation that never landed.
type vanishingStore struct{ *MemStore }

func (vanishingStore) SetDisabled(context.Context, string, bool) (User, bool, error) {
	return User{}, false, nil
}

func TestDisableRaceIsNotReportedAsSuccess(t *testing.T) {
	s, _ := newTestServerUsers(t, func(m *MemStore) UserStore { return vanishingStore{m} })

	if w := do(t, s, "alice", "POST", "/v1/users/u-eng/disable", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("user vanished before the write: got %d, want 404: %s", w.Code, w.Body)
	}
	var resp struct{ Events []AuditEvent }
	do(t, s, "root", "GET", "/v1/audit", "", &resp)
	for _, e := range resp.Events {
		if e.Allowed {
			t.Errorf("allowed:true audited for a mutation that never landed: %+v", e)
		}
	}
}

// The audit write used to live in one shared helper; it now lives at seven
// independent call sites, so every action name needs its own pin.
func TestEveryMutationAuditsItsSuccess(t *testing.T) {
	s, _ := newTestServer(t)

	for _, c := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/v1/roles", `{"name":"tmp","grants":["audit:read"]}`, http.StatusCreated},
		{"PUT", "/v1/roles/tmp", `{"name":"tmp","grants":["audit:read","users:read"]}`, http.StatusOK},
		{"POST", "/v1/assignments", `{"subject":"zed","role":"tmp"}`, http.StatusCreated},
		{"POST", "/v1/assignments/revoke", `{"subject":"zed","role":"tmp"}`, http.StatusNoContent},
		{"DELETE", "/v1/roles/tmp", "", http.StatusNoContent},
		{"POST", "/v1/users/u-eng/disable", "", http.StatusOK},
		{"POST", "/v1/sessions/sess-eng/revoke", "", http.StatusNoContent},
	} {
		if w := do(t, s, "root", c.method, c.path, c.body, nil); w.Code != c.want {
			t.Fatalf("%s %s: got %d, want %d: %s", c.method, c.path, w.Code, c.want, w.Body)
		}
	}

	var resp struct{ Events []AuditEvent }
	do(t, s, "root", "GET", "/v1/audit", "", &resp)
	got := map[string]bool{}
	for _, e := range resp.Events {
		if e.Allowed {
			got[e.Action] = true
		}
	}
	for _, action := range []string{
		"role.create", "role.update", "role.delete",
		"assignment.create", "assignment.revoke",
		"user.disable", "session.revoke",
	} {
		if !got[action] {
			t.Errorf("%s landed but was never audited: %+v", action, resp.Events)
		}
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

// carveOut gives sub a realm-scoped deny for the three target-addressed routes:
// the shape that makes "allowed at global" stop implying "allowed for any
// target", since deny > allow and a realm assignment does not cover a global
// check.
func carveOut(t *testing.T, s *Server, sub, realm string) {
	t.Helper()
	if err := s.cfg.Engine.DefineRole(rbac.Role{
		Name:   "carve-out",
		Denies: []rbac.Permission{"users:write", "sessions:read", "sessions:revoke"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Engine.Assign(rbac.Assignment{Subject: sub, Role: "carve-out", Scope: rbac.Scope{Realm: realm}}); err != nil {
		t.Fatal(err)
	}
}

// A session whose owner is gone has no realm, so the check can only fall back
// to global — safe only for a caller allowed for every target. A realm-scoped
// caller, or a global holder with a realm deny carve-out, is refused; a caller
// who is authorized everywhere must still be able to revoke it, because a
// session outliving its user record is exactly the state after a user deletion.
func TestRevokeOrphanedSession(t *testing.T) {
	s, store := newTestServer(t)
	store.AddSession(Session{ID: "sess-orphan", UserID: "u-gone", CreatedAt: time.Unix(1e9, 0)})
	carveOut(t, s, "olivia", "finance")

	for _, sub := range []string{"alice", "olivia"} {
		if w := do(t, s, sub, "POST", "/v1/sessions/sess-orphan/revoke", "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403: %s", sub, w.Code, w.Body)
		}
		if _, ok, _ := store.Session(context.Background(), "sess-orphan"); !ok {
			t.Fatalf("%s revoked an orphan without being authorized for every target", sub)
		}
	}

	if w := do(t, s, "root", "POST", "/v1/sessions/sess-orphan/revoke", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("global holder revoking an orphan: got %d, want 204: %s", w.Code, w.Body)
	}
	if _, ok, _ := store.Session(context.Background(), "sess-orphan"); ok {
		t.Error("orphaned session still live after a 204")
	}
}

// vanishingSessions models the revoke race once sessions live in
// sessiond/Redis: the pre-authorization lookup finds the session, the revoke
// does not. 204 plus an allowed:true event would claim a revoke that never
// landed — the users:write defect, at its sibling call site.
type vanishingSessions struct{ *MemStore }

func (vanishingSessions) RevokeSession(context.Context, string) (bool, error) { return false, nil }

func TestRevokeRaceIsNotReportedAsSuccess(t *testing.T) {
	s, store := newTestServer(t)
	s.cfg.Sessions = vanishingSessions{store}

	if w := do(t, s, "olivia", "POST", "/v1/sessions/sess-eng/revoke", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("session vanished before the write: got %d, want 404: %s", w.Code, w.Body)
	}
	var resp struct{ Events []AuditEvent }
	do(t, s, "root", "GET", "/v1/audit", "", &resp)
	for _, e := range resp.Events {
		if e.Allowed {
			t.Errorf("allowed:true audited for a revoke that never landed: %+v", e)
		}
	}
}

// The realm-derived scope forces a lookup before the check; a bare 404 would
// then tell an unauthorized caller which user and session IDs exist in realms
// they cannot read, and leave no trace of the scan.
func TestTargetEnumeration(t *testing.T) {
	s, _ := newTestServer(t)

	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/users/ghost/disable"},
		{"GET", "/v1/users/ghost/sessions"},
		{"POST", "/v1/sessions/ghost/revoke"},
	} {
		if w := do(t, s, "alice", c.method, c.path, "", nil); w.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403 (same shape as a cross-realm hit)", c.method, c.path, w.Code)
		}
	}

	// The denied probes are in the trail; a scan must not be invisible.
	var resp struct{ Events []AuditEvent }
	do(t, s, "root", "GET", "/v1/audit", "", &resp)
	if len(resp.Events) != 2 { // user.disable + session.revoke (listSessions is not a mutation)
		t.Errorf("got %d audited probes, want 2: %+v", len(resp.Events), resp.Events)
	}

	// A caller authorized for any target learns nothing from a 404, so they
	// keep the honest answer.
	if w := do(t, s, "root", "POST", "/v1/users/ghost/disable", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("global holder: got %d, want 404", w.Code)
	}
	if w := do(t, s, "vera", "GET", "/v1/users/ghost/sessions", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("global reader: got %d, want 404", w.Code)
	}

	// The status code is not the whole oracle: a 403 whose message or decision
	// names the scope tells the caller whether it was checked at global (miss)
	// or at the target's realm (cross-realm hit), and leaks that realm besides.
	// The two responses must be byte-identical.
	for _, c := range []struct{ method, miss, hit string }{
		{"POST", "/v1/users/ghost/disable", "/v1/users/u-fin/disable"},
		{"GET", "/v1/users/ghost/sessions", "/v1/users/u-fin/sessions"},
		{"POST", "/v1/sessions/ghost/revoke", "/v1/sessions/sess-fin/revoke"},
	} {
		miss := do(t, s, "alice", c.method, c.miss, "", nil)
		hit := do(t, s, "alice", c.method, c.hit, "", nil)
		if miss.Code != http.StatusForbidden || hit.Code != http.StatusForbidden {
			t.Fatalf("%s: miss %d, hit %d, want 403 both", c.miss, miss.Code, hit.Code)
		}
		if miss.Body.String() != hit.Body.String() {
			t.Errorf("%s: the 403 body still discloses existence\n miss: %s hit:  %s",
				c.miss, miss.Body, hit.Body)
		}
	}
}

// "Allowed at global ⇒ allowed for any target" is what buys the honest 404 on a
// miss, and a realm-scoped deny carve-out falsifies it: the holder is allowed at
// global and denied in one realm, so a 404 on a miss beside a 403 on a hit in
// that realm restores the very oracle requireTarget closes.
func TestTargetEnumerationWithRealmDeny(t *testing.T) {
	s, _ := newTestServer(t)
	carveOut(t, s, "olivia", "finance")

	for _, c := range []struct{ method, miss, hit string }{
		{"POST", "/v1/users/ghost/disable", "/v1/users/u-fin/disable"},
		{"GET", "/v1/users/ghost/sessions", "/v1/users/u-fin/sessions"},
		{"POST", "/v1/sessions/ghost/revoke", "/v1/sessions/sess-fin/revoke"},
	} {
		miss := do(t, s, "olivia", c.method, c.miss, "", nil)
		hit := do(t, s, "olivia", c.method, c.hit, "", nil)
		if miss.Code != hit.Code || miss.Body.String() != hit.Body.String() {
			t.Errorf("%s %s: the carve-out holder can still enumerate\n miss: %d %s hit:  %d %s",
				c.method, c.miss, miss.Code, miss.Body, hit.Code, hit.Body)
		}
	}
	// The carve-out costs her nothing in the realms she is not carved out of.
	if w := do(t, s, "olivia", "POST", "/v1/users/u-eng/disable", "", nil); w.Code != http.StatusOK {
		t.Errorf("uncarved realm: got %d, want 200: %s", w.Code, w.Body)
	}

	// The response is not the whole oracle either: she holds audit:read at
	// global, so she reads her own probe rows back. A per-branch Scope there
	// ("global" for the miss, "realm:finance" for the cross-realm hit) tells
	// her both that the id exists and which realm it is in.
	var resp struct{ Events []AuditEvent }
	if w := do(t, s, "olivia", "GET", "/v1/audit", "", &resp); w.Code != http.StatusOK {
		t.Fatalf("carve-out holder reading her own trail: %d", w.Code)
	}
	for _, e := range resp.Events {
		if !e.Allowed && e.Scope != rbac.Global.String() {
			t.Errorf("denial event discloses the checked scope: %+v", e)
		}
	}
}

func TestAuditTrail(t *testing.T) {
	s, _ := newTestServer(t)
	// One allowed and one denied mutation, both must land in the trail.
	do(t, s, "root", "POST", "/v1/roles", `{"name":"tmp","grants":["audit:read"]}`, nil)
	do(t, s, "olivia", "POST", "/v1/roles", `{"name":"nope","grants":["audit:read"]}`, nil)
	// Authorized but failed mutations changed nothing, so they must not leave
	// an allowed:true event claiming they did.
	if w := do(t, s, "root", "POST", "/v1/assignments", `{"subject":"zed","role":"ghost"}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: got %d, want 400", w.Code)
	}
	if w := do(t, s, "root", "DELETE", "/v1/roles/viewer", "", nil); w.Code != http.StatusConflict {
		t.Fatalf("delete builtin: got %d, want 409", w.Code)
	}

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
	// A role write must be reconstructable from its event alone.
	if !strings.Contains(resp.Events[1].Detail, "audit:read") {
		t.Errorf("role write audited with no content: %+v", resp.Events[1])
	}
	// audit:read is global-only: realm-admin alice holds it only in her realm.
	if w := do(t, s, "alice", "GET", "/v1/audit", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("realm-admin reading global audit: got %d, want 403", w.Code)
	}
}

// A panic before anything is written still answers 500; a panic after the
// response is committed must leave the body alone — appending an error
// envelope to a flushed body makes it invalid JSON and desynchronizes the
// access log from the status the client actually saw.
func TestPanicRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serve := func(h http.HandlerFunc) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		withRequestLog(logger, h).ServeHTTP(w, httptest.NewRequest("GET", "/v1/roles", nil))
		return w
	}

	w := serve(func(http.ResponseWriter, *http.Request) { panic("before write") })
	if w.Code != http.StatusInternalServerError {
		t.Errorf("panic before write: got %d, want 500", w.Code)
	}

	w = serve(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		panic("after write")
	})
	if w.Code != http.StatusOK {
		t.Errorf("committed status changed to %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Errorf("recover path corrupted the committed body: %v\n%s", err, w.Body)
	}

	// A bare Write commits the response too, with net/http's implicit 200 —
	// tracking only WriteHeader misses it.
	w = serve(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		panic("after implicit write")
	})
	if w.Code != http.StatusOK {
		t.Errorf("implicitly committed status changed to %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Errorf("recover path corrupted the implicitly committed body: %v\n%s", err, w.Body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	h := do(t, s, "vera", "GET", "/v1/roles", "", nil).Header()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %q", want, csp)
		}
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("security headers dropped: %+v", h)
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
