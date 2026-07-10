package rbac

import (
	"strings"
	"sync"
	"testing"
)

func mustDefine(t *testing.T, e *Engine, r Role) {
	t.Helper()
	if err := e.DefineRole(r); err != nil {
		t.Fatalf("DefineRole(%q): %v", r.Name, err)
	}
}

func mustAssign(t *testing.T, e *Engine, a Assignment) {
	t.Helper()
	if err := e.Assign(a); err != nil {
		t.Fatalf("Assign(%+v): %v", a, err)
	}
}

func TestPermissionValidate(t *testing.T) {
	tests := []struct {
		perm    Permission
		wantErr bool
	}{
		{"users:read", false},
		{"users:*", false},
		{"*:*", false},
		{"a-b_1:c-d_2", false},
		{"users", true},        // no action
		{"*:read", true},       // wildcard resource, concrete action
		{"Users:read", true},   // uppercase
		{"users:read:x", true}, // extra segment
		{"users:", true},       // empty action
		{":read", true},        // empty resource
		{"", true},
	}
	for _, tt := range tests {
		if err := tt.perm.Validate(); (err != nil) != tt.wantErr {
			t.Errorf("Validate(%q) err=%v, wantErr=%v", tt.perm, err, tt.wantErr)
		}
	}
	if err := Permission("users:*").ValidateConcrete(); err == nil {
		t.Error("ValidateConcrete accepted a wildcard")
	}
	if err := Permission("users:read").ValidateConcrete(); err != nil {
		t.Errorf("ValidateConcrete(users:read): %v", err)
	}
}

func TestPermissionMatches(t *testing.T) {
	tests := []struct {
		pattern, query Permission
		want           bool
	}{
		{"users:read", "users:read", true},
		{"users:read", "users:write", false},
		{"users:read", "roles:read", false},
		{"users:*", "users:delete", true},
		{"users:*", "roles:read", false},
		{"*:*", "anything:at_all", true},
	}
	for _, tt := range tests {
		if got := tt.pattern.Matches(tt.query); got != tt.want {
			t.Errorf("%q.Matches(%q) = %v, want %v", tt.pattern, tt.query, got, tt.want)
		}
	}
}

func TestBuiltinCatalog(t *testing.T) {
	e := New()
	for _, name := range []string{RoleViewer, RoleOperator, RoleRealmAdmin, RoleSuperAdmin} {
		r, ok := e.Role(name)
		if !ok || !r.Builtin {
			t.Errorf("builtin role %q missing or not marked builtin", name)
		}
	}
	if err := e.DefineRole(Role{Name: RoleViewer, Grants: []Permission{"*:*"}}); err == nil {
		t.Error("DefineRole allowed shadowing a builtin")
	}
	if err := e.DeleteRole(RoleSuperAdmin); err == nil {
		t.Error("DeleteRole allowed deleting a builtin")
	}
}

func TestCheckMatrix(t *testing.T) {
	eng := Scope{Realm: "engineering"}
	fin := Scope{Realm: "finance"}

	e := New()
	// Custom role with a deny carve-out on top of a wildcard grant.
	mustDefine(t, e, Role{
		Name:   "users-admin-no-delete",
		Grants: []Permission{"users:*"},
		Denies: []Permission{"users:delete"},
	})
	// Deep inheritance: l3 -> l2 -> l1.
	mustDefine(t, e, Role{Name: "l1", Grants: []Permission{"audit:read"}})
	mustDefine(t, e, Role{Name: "l2", Extends: "l1", Grants: []Permission{"sessions:read"}})
	mustDefine(t, e, Role{Name: "l3", Extends: "l2", Grants: []Permission{"users:read"}})
	// Exact deny in a parent vs wildcard allow in the child.
	mustDefine(t, e, Role{Name: "base-deny", Denies: []Permission{"roles:write"}})
	mustDefine(t, e, Role{Name: "wide-child", Extends: "base-deny", Grants: []Permission{"roles:*"}})

	mustAssign(t, e, Assignment{Subject: "root", Role: RoleSuperAdmin, Scope: Global})
	mustAssign(t, e, Assignment{Subject: "alice", Role: RoleRealmAdmin, Scope: eng})
	mustAssign(t, e, Assignment{Subject: "bob", Role: RoleOperator, Scope: Global})
	mustAssign(t, e, Assignment{Subject: "carol", Role: "users-admin-no-delete", Scope: Global})
	mustAssign(t, e, Assignment{Subject: "dave", Role: "l3", Scope: Global})
	mustAssign(t, e, Assignment{Subject: "erin", Role: "wide-child", Scope: Global})

	tests := []struct {
		name    string
		subject string
		perm    Permission
		scope   Scope
		want    bool
		effect  Effect
	}{
		{"super-admin anything global", "root", "roles:write", Global, true, EffectAllow},
		{"super-admin anything in a realm", "root", "users:delete", eng, true, EffectAllow},
		{"realm-admin in own realm", "alice", "users:write", eng, true, EffectAllow},
		{"realm-admin assigns in own realm", "alice", "assignments:write", eng, true, EffectAllow},
		{"scope isolation: other realm", "alice", "users:write", fin, false, EffectDefaultDeny},
		{"scope isolation: global", "alice", "users:write", Global, false, EffectDefaultDeny},
		{"operator can revoke sessions", "bob", "sessions:revoke", eng, true, EffectAllow},
		{"operator inherits viewer read", "bob", "audit:read", Global, true, EffectAllow},
		{"operator cannot write roles", "bob", "roles:write", Global, false, EffectDefaultDeny},
		{"wildcard grant allows", "carol", "users:disable", Global, true, EffectAllow},
		{"exact deny beats wildcard allow", "carol", "users:delete", Global, false, EffectDeny},
		{"deep inheritance leaf", "dave", "users:read", Global, true, EffectAllow},
		{"deep inheritance middle", "dave", "sessions:read", Global, true, EffectAllow},
		{"deep inheritance root", "dave", "audit:read", Global, true, EffectAllow},
		{"deep inheritance no bleed", "dave", "users:write", Global, false, EffectDefaultDeny},
		{"inherited exact deny beats child wildcard allow", "erin", "roles:write", Global, false, EffectDeny},
		{"deny carve-out only where matched", "erin", "roles:read", Global, true, EffectAllow},
		{"unknown subject", "mallory", "users:read", Global, false, EffectDefaultDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Check(tt.subject, tt.perm, tt.scope)
			if d.Allowed != tt.want || d.Effect != tt.effect {
				t.Fatalf("Check(%s, %s, %s) = allowed=%v effect=%s, want allowed=%v effect=%s",
					tt.subject, tt.perm, tt.scope, d.Allowed, d.Effect, tt.want, tt.effect)
			}
			if tt.effect == EffectDefaultDeny && d.Decider != nil {
				t.Errorf("default deny must have nil decider, got %+v", d.Decider)
			}
			if tt.effect != EffectDefaultDeny && d.Decider == nil {
				t.Errorf("decided outcome must carry a decider")
			}
		})
	}
}

// TestDenyOverridesAllowAcrossAssignments: a deny from one assignment vetoes
// an allow from a different assignment of the same subject.
func TestDenyOverridesAllowAcrossAssignments(t *testing.T) {
	e := New()
	mustDefine(t, e, Role{Name: "suspended", Denies: []Permission{"*:*"}})
	mustAssign(t, e, Assignment{Subject: "s", Role: RoleSuperAdmin, Scope: Global})
	mustAssign(t, e, Assignment{Subject: "s", Role: "suspended", Scope: Global})

	d := e.Check("s", "users:read", Global)
	if d.Allowed || d.Effect != EffectDeny {
		t.Fatalf("deny must override allow across assignments: %+v", d)
	}
	if d.Decider.Role != "suspended" || d.Decider.Rule != "*:*" {
		t.Errorf("decider = %+v, want suspended / *:*", d.Decider)
	}
}

func TestExplanationTrace(t *testing.T) {
	eng := Scope{Realm: "engineering"}
	fin := Scope{Realm: "finance"}

	e := New()
	mustAssign(t, e, Assignment{Subject: "alice", Role: RoleRealmAdmin, Scope: eng})
	mustAssign(t, e, Assignment{Subject: "alice", Role: RoleViewer, Scope: fin})

	t.Run("allow via inherited role", func(t *testing.T) {
		d := e.Check("alice", "users:write", eng)
		if !d.Allowed {
			t.Fatalf("want allow, got %+v", d)
		}
		// Decider: eng assignment -> realm-admin chain -> operator's users:write.
		want := Match{
			Assignment: Assignment{Subject: "alice", Role: RoleRealmAdmin, Scope: eng},
			Role:       RoleOperator,
			Rule:       "users:write",
			Effect:     EffectAllow,
		}
		if *d.Decider != want {
			t.Errorf("decider = %+v, want %+v", *d.Decider, want)
		}
		if len(d.Trace) != 2 {
			t.Fatalf("trace covers %d assignments, want 2", len(d.Trace))
		}
		// The eng assignment matched scope and walked the full chain.
		at := d.Trace[0]
		if !at.ScopeMatch {
			t.Fatal("engineering assignment should scope-match")
		}
		var chain []string
		for _, rt := range at.Chain {
			chain = append(chain, rt.Role)
		}
		if got, want := strings.Join(chain, ","), "realm-admin,operator,viewer"; got != want {
			t.Errorf("chain = %s, want %s", got, want)
		}
		if len(at.Chain[1].MatchedGrants) != 1 || at.Chain[1].MatchedGrants[0] != "users:write" {
			t.Errorf("operator trace grants = %v, want [users:write]", at.Chain[1].MatchedGrants)
		}
		// The finance viewer assignment is in the trace but scope-mismatched.
		if d.Trace[1].ScopeMatch || d.Trace[1].Chain != nil {
			t.Errorf("finance assignment should be traced as scope mismatch with no chain: %+v", d.Trace[1])
		}
	})

	t.Run("default deny still traces near misses", func(t *testing.T) {
		d := e.Check("alice", "users:write", fin)
		if d.Allowed || d.Effect != EffectDefaultDeny || d.Decider != nil {
			t.Fatalf("want default deny, got %+v", d)
		}
		if len(d.Trace) != 2 {
			t.Fatalf("trace covers %d assignments, want 2", len(d.Trace))
		}
		// eng realm-admin: scope mismatch. fin viewer: scope match, no grant.
		if d.Trace[0].ScopeMatch {
			t.Error("engineering assignment must not scope-match a finance check")
		}
		viewerTrace := d.Trace[1]
		if !viewerTrace.ScopeMatch || len(viewerTrace.Chain) != 1 {
			t.Fatalf("finance viewer should match scope with a 1-role chain: %+v", viewerTrace)
		}
		if len(viewerTrace.Chain[0].MatchedGrants) != 0 {
			t.Errorf("viewer must not match users:write: %+v", viewerTrace.Chain[0])
		}
	})

	t.Run("deny decider is traced", func(t *testing.T) {
		e2 := New()
		mustDefine(t, e2, Role{Name: "capped", Grants: []Permission{"users:*"}, Denies: []Permission{"users:delete"}})
		mustAssign(t, e2, Assignment{Subject: "s", Role: "capped", Scope: Global})
		d := e2.Check("s", "users:delete", Global)
		if d.Allowed || d.Decider == nil || d.Decider.Effect != EffectDeny || d.Decider.Rule != "users:delete" {
			t.Fatalf("want deny decided by users:delete, got %+v", d)
		}
		rt := d.Trace[0].Chain[0]
		if len(rt.MatchedDenies) != 1 || len(rt.MatchedGrants) != 1 {
			t.Errorf("trace should show both the matched grant and the matched deny: %+v", rt)
		}
	})
}

func TestDefineRoleValidation(t *testing.T) {
	e := New()
	tests := []struct {
		name string
		role Role
	}{
		{"empty name", Role{Name: ""}},
		{"bad name", Role{Name: "Bad Name"}},
		{"bad grant", Role{Name: "x", Grants: []Permission{"nope"}}},
		{"bad deny", Role{Name: "x", Denies: []Permission{"*:read"}}},
		{"unknown parent", Role{Name: "x", Extends: "ghost"}},
		{"self cycle", Role{Name: "x", Extends: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := e.DefineRole(tt.role); err == nil {
				t.Errorf("DefineRole(%+v) succeeded, want error", tt.role)
			}
		})
	}
}

func TestInheritanceCycleRejected(t *testing.T) {
	e := New()
	mustDefine(t, e, Role{Name: "a"})
	mustDefine(t, e, Role{Name: "b", Extends: "a"})
	mustDefine(t, e, Role{Name: "c", Extends: "b"})
	// Closing the loop a -> c would make a -> c -> b -> a.
	if err := e.DefineRole(Role{Name: "a", Extends: "c"}); err == nil {
		t.Fatal("redefining a to extend c must be rejected as a cycle")
	}
	// A legitimate re-parent still works.
	mustDefine(t, e, Role{Name: "c", Extends: "a"})
}

func TestDeleteRoleGuards(t *testing.T) {
	e := New()
	mustDefine(t, e, Role{Name: "parent"})
	mustDefine(t, e, Role{Name: "child", Extends: "parent"})
	if err := e.DeleteRole("parent"); err == nil {
		t.Error("deleting an extended role must fail")
	}
	mustDefine(t, e, Role{Name: "assigned"})
	mustAssign(t, e, Assignment{Subject: "s", Role: "assigned"})
	if err := e.DeleteRole("assigned"); err == nil {
		t.Error("deleting a role with assignments must fail")
	}
	if err := e.DeleteRole("ghost"); err == nil {
		t.Error("deleting an unknown role must fail")
	}
	if err := e.DeleteRole("child"); err != nil {
		t.Errorf("deleting an unreferenced custom role: %v", err)
	}
}

func TestAssignRevoke(t *testing.T) {
	e := New()
	if err := e.Assign(Assignment{Subject: "s", Role: "ghost"}); err == nil {
		t.Error("assigning an unknown role must fail")
	}
	if err := e.Assign(Assignment{Role: RoleViewer}); err == nil {
		t.Error("assigning an empty subject must fail")
	}
	a := Assignment{Subject: "s", Role: RoleViewer, Scope: Scope{Realm: "r"}}
	mustAssign(t, e, a)
	mustAssign(t, e, a) // idempotent
	if got := len(e.Assignments("s")); got != 1 {
		t.Fatalf("duplicate assignment stored: %d", got)
	}
	if !e.Revoke(a) {
		t.Error("Revoke of existing assignment returned false")
	}
	if e.Revoke(a) {
		t.Error("Revoke of missing assignment returned true")
	}
	if e.Check("s", "users:read", Scope{Realm: "r"}).Allowed {
		t.Error("revoked assignment still grants")
	}
}

func TestMalformedQueryDefaultDenies(t *testing.T) {
	e := New()
	mustAssign(t, e, Assignment{Subject: "s", Role: RoleSuperAdmin})
	for _, q := range []Permission{"users:*", "*:*", "nope", ""} {
		if d := e.Check("s", q, Global); d.Allowed {
			t.Errorf("malformed query %q allowed", q)
		}
	}
}

// TestConcurrency exercises the engine under -race.
func TestConcurrency(t *testing.T) {
	e := New()
	mustAssign(t, e, Assignment{Subject: "s", Role: RoleViewer})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				e.Check("s", "users:read", Global)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				a := Assignment{Subject: "s", Role: RoleOperator}
				_ = e.Assign(a)
				e.Revoke(a)
			}
		}()
	}
	wg.Wait()
}
