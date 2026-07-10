// Package rbac implements the Meridian authorization model: a pure,
// I/O-free RBAC engine whose distinguishing feature is that every decision
// carries a full explanation trace.
//
// Model:
//
//   - A Permission is "resource:action" ("users:read"). "users:*" matches
//     every action on users; "*:*" matches everything. A wildcard resource
//     with a concrete action ("*:read") is rejected — it invites accidental
//     over-grants and has no honest use case here.
//   - A Role bundles permission grants and optional explicit denies, and may
//     extend exactly one parent role (single inheritance, cycles rejected at
//     definition time).
//   - An Assignment binds a subject to a role at a Scope: global, or one
//     realm. A realm-scoped assignment confers nothing outside its realm.
//
// Precedence, in order: explicit deny > allow > default deny. A deny
// anywhere in any matching assignment's role chain vetoes every allow,
// including an exact allow vetoed by a wildcard deny and vice versa —
// specificity never outranks effect. With no matching rule at all the
// answer is deny (deny-by-default).
//
// Check returns a Decision whose Trace records every assignment considered
// — including those skipped for scope mismatch — the role chain walked, and
// the exact rule that decided the outcome. The trace is the product, not a
// debug aid: the console API and UI render it verbatim to answer "why can
// Alice delete users in realm engineering?".
package rbac

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Permission is a "resource:action" pattern. Grants and denies may use a
// wildcard action ("users:*") or the full wildcard ("*:*"); queries passed
// to Check must be concrete.
type Permission string

var partRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// parts splits a permission, without validation.
func (p Permission) parts() (resource, action string) {
	res, act, _ := strings.Cut(string(p), ":")
	return res, act
}

// Validate checks pattern syntax (wildcards allowed).
func (p Permission) Validate() error {
	res, act, ok := strings.Cut(string(p), ":")
	if !ok {
		return fmt.Errorf("permission %q: want resource:action", p)
	}
	if res == "*" {
		if act != "*" {
			return fmt.Errorf("permission %q: wildcard resource requires wildcard action", p)
		}
		return nil
	}
	if !partRE.MatchString(res) {
		return fmt.Errorf("permission %q: invalid resource", p)
	}
	if act != "*" && !partRE.MatchString(act) {
		return fmt.Errorf("permission %q: invalid action", p)
	}
	return nil
}

// ValidateConcrete checks that p is a concrete (wildcard-free) permission,
// as required for Check queries.
func (p Permission) ValidateConcrete() error {
	if err := p.Validate(); err != nil {
		return err
	}
	if strings.Contains(string(p), "*") {
		return fmt.Errorf("permission %q: query must be concrete, not a wildcard", p)
	}
	return nil
}

// Matches reports whether pattern p covers concrete permission q.
func (p Permission) Matches(q Permission) bool {
	pr, pa := p.parts()
	qr, qa := q.parts()
	if pr == "*" {
		return true // syntax guarantees action is also *
	}
	return pr == qr && (pa == "*" || pa == qa)
}

// Scope is where an assignment applies: the zero value is global; a
// non-empty Realm restricts the assignment to that realm.
type Scope struct {
	Realm string `json:"realm,omitempty"`
}

// Global is the unrestricted scope.
var Global = Scope{}

// IsGlobal reports whether s is the global scope.
func (s Scope) IsGlobal() bool { return s.Realm == "" }

func (s Scope) String() string {
	if s.IsGlobal() {
		return "global"
	}
	return "realm:" + s.Realm
}

// covers reports whether an assignment at scope s applies to a check at
// scope q: global covers everything; a realm covers only itself.
func (s Scope) covers(q Scope) bool {
	return s.IsGlobal() || s == q
}

// Role bundles grants and denies, optionally extending one parent.
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Extends     string       `json:"extends,omitempty"`
	Grants      []Permission `json:"grants"`
	Denies      []Permission `json:"denies,omitempty"`
	Builtin     bool         `json:"builtin"`
}

// Assignment binds a subject to a role at a scope.
type Assignment struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Scope   Scope  `json:"scope"`
}

// Effect is the outcome class of a decision.
type Effect string

const (
	EffectAllow       Effect = "allow"
	EffectDeny        Effect = "deny"
	EffectDefaultDeny Effect = "default_deny"
)

// Match identifies the exact rule that produced an effect: which
// assignment, which role in its inheritance chain, and which pattern.
type Match struct {
	Assignment Assignment `json:"assignment"`
	Role       string     `json:"role"` // the chain role holding the rule
	Rule       Permission `json:"rule"` // the grant/deny pattern that matched
	Effect     Effect     `json:"effect"`
}

// RoleTrace records one role in an inheritance chain and the rules in it
// that matched the query.
type RoleTrace struct {
	Role          string       `json:"role"`
	MatchedGrants []Permission `json:"matched_grants,omitempty"`
	MatchedDenies []Permission `json:"matched_denies,omitempty"`
}

// AssignmentTrace records the evaluation of one assignment: whether its
// scope covered the query, and the role chain walked if it did.
type AssignmentTrace struct {
	Assignment Assignment  `json:"assignment"`
	ScopeMatch bool        `json:"scope_match"`
	Chain      []RoleTrace `json:"chain,omitempty"` // assigned role first, ancestors after
}

// Decision is the full answer to a Check: verdict, the rule that decided
// it (nil for default deny), and the complete evaluation trace.
type Decision struct {
	Subject    string            `json:"subject"`
	Permission Permission        `json:"permission"`
	Scope      Scope             `json:"scope"`
	Allowed    bool              `json:"allowed"`
	Effect     Effect            `json:"effect"`
	Decider    *Match            `json:"decider,omitempty"`
	Trace      []AssignmentTrace `json:"trace"`
}

// Engine holds role definitions and assignments and answers Check queries.
// Safe for concurrent use. It performs no I/O; persistence is the caller's
// concern (the console server keeps it in memory and documents the
// Postgres seam).
type Engine struct {
	mu          sync.RWMutex
	roles       map[string]Role
	assignments []Assignment
}

// Builtin role names.
const (
	RoleViewer     = "viewer"
	RoleOperator   = "operator"
	RoleRealmAdmin = "realm-admin"
	RoleSuperAdmin = "super-admin"
)

// New returns an engine seeded with the built-in role catalog:
//
//	viewer      read-only across the console
//	operator    viewer + user lifecycle + session revocation
//	realm-admin operator + assignment management (meant for realm scope)
//	super-admin *:* (meant for global scope)
//
// Built-ins cannot be modified or deleted.
func New() *Engine {
	e := &Engine{roles: make(map[string]Role)}
	for _, r := range []Role{
		{
			Name:        RoleViewer,
			Description: "Read-only visibility into users, roles, assignments, sessions, and audit.",
			Grants: []Permission{
				"users:read", "roles:read", "assignments:read",
				"sessions:read", "audit:read", "permissions:read", "authz:explain",
			},
			Builtin: true,
		},
		{
			Name:        RoleOperator,
			Description: "Day-to-day operations: user lifecycle and session revocation.",
			Extends:     RoleViewer,
			Grants:      []Permission{"users:write", "sessions:revoke"},
			Builtin:     true,
		},
		{
			Name:        RoleRealmAdmin,
			Description: "Full administration within an assigned realm (assign with realm scope).",
			Extends:     RoleOperator,
			Grants:      []Permission{"assignments:write"},
			Builtin:     true,
		},
		{
			Name:        RoleSuperAdmin,
			Description: "Unrestricted administration (assign with global scope).",
			Grants:      []Permission{"*:*"},
			Builtin:     true,
		},
	} {
		e.roles[r.Name] = r
	}
	return e
}

// DefineRole creates or replaces a custom role. It rejects invalid
// permission syntax, unknown or self parents, inheritance cycles, and any
// attempt to shadow a built-in role.
func (e *Engine) DefineRole(r Role) error {
	if r.Name == "" || !partRE.MatchString(r.Name) {
		return fmt.Errorf("role name %q: must match [a-z0-9_-]+", r.Name)
	}
	for _, p := range append(append([]Permission{}, r.Grants...), r.Denies...) {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.roles[r.Name]; ok && existing.Builtin {
		return fmt.Errorf("role %q is built-in and cannot be modified", r.Name)
	}
	r.Builtin = false
	if r.Extends != "" {
		if _, ok := e.roles[r.Extends]; !ok && r.Extends != r.Name {
			return fmt.Errorf("role %q extends unknown role %q", r.Name, r.Extends)
		}
		// Walk up from the proposed parent; reaching r.Name again is a cycle.
		for cur := r.Extends; cur != ""; {
			if cur == r.Name {
				return fmt.Errorf("role %q: inheritance cycle via %q", r.Name, r.Extends)
			}
			cur = e.roles[cur].Extends
		}
	}
	e.roles[r.Name] = r
	return nil
}

// DeleteRole removes a custom role. Built-ins, roles extended by another
// role, and roles with live assignments are protected.
func (e *Engine) DeleteRole(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.roles[name]
	if !ok {
		return fmt.Errorf("role %q not found", name)
	}
	if r.Builtin {
		return fmt.Errorf("role %q is built-in and cannot be deleted", name)
	}
	for _, other := range e.roles {
		if other.Extends == name {
			return fmt.Errorf("role %q is extended by %q", name, other.Name)
		}
	}
	for _, a := range e.assignments {
		if a.Role == name {
			return fmt.Errorf("role %q has active assignments", name)
		}
	}
	delete(e.roles, name)
	return nil
}

// Role returns a role by name.
func (e *Engine) Role(name string) (Role, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r, ok := e.roles[name]
	return r, ok
}

// Roles returns all roles, sorted by name.
func (e *Engine) Roles() []Role {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Role, 0, len(e.roles))
	for _, r := range e.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Assign binds subject → role at scope. The role must exist; duplicate
// assignments are idempotent.
func (e *Engine) Assign(a Assignment) error {
	if a.Subject == "" {
		return fmt.Errorf("assignment: empty subject")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.roles[a.Role]; !ok {
		return fmt.Errorf("assignment: unknown role %q", a.Role)
	}
	for _, ex := range e.assignments {
		if ex == a {
			return nil
		}
	}
	e.assignments = append(e.assignments, a)
	return nil
}

// Revoke removes an exact assignment, reporting whether it existed.
func (e *Engine) Revoke(a Assignment) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, ex := range e.assignments {
		if ex == a {
			e.assignments = append(e.assignments[:i], e.assignments[i+1:]...)
			return true
		}
	}
	return false
}

// Assignments returns all assignments; subject filters if non-empty.
func (e *Engine) Assignments(subject string) []Assignment {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Assignment, 0, len(e.assignments))
	for _, a := range e.assignments {
		if subject == "" || a.Subject == subject {
			out = append(out, a)
		}
	}
	return out
}

// chain returns the inheritance chain starting at name (assigned role
// first). Definition-time cycle rejection makes this loop finite.
func (e *Engine) chain(name string) []Role {
	var out []Role
	for cur := name; cur != ""; {
		r, ok := e.roles[cur]
		if !ok {
			break // parent deleted out from under us; treat chain as ending
		}
		out = append(out, r)
		cur = r.Extends
	}
	return out
}

// Check evaluates whether subject holds perm at scope and explains why.
// perm must be concrete. Precedence: deny > allow > default deny; the
// first deny found (in assignment order, chain order) is the decider,
// otherwise the first allow, otherwise default deny with a full trace of
// everything that was considered and didn't grant.
func (e *Engine) Check(subject string, perm Permission, scope Scope) Decision {
	d := Decision{Subject: subject, Permission: perm, Scope: scope, Effect: EffectDefaultDeny}
	if err := perm.ValidateConcrete(); err != nil {
		// Malformed queries fall through to default deny with an empty
		// trace; the API layer validates first and reports 400.
		return d
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var firstDeny, firstAllow *Match
	for _, a := range e.assignments {
		if a.Subject != subject {
			continue
		}
		at := AssignmentTrace{Assignment: a, ScopeMatch: a.Scope.covers(scope)}
		if at.ScopeMatch {
			for _, r := range e.chain(a.Role) {
				rt := RoleTrace{Role: r.Name}
				for _, p := range r.Denies {
					if p.Matches(perm) {
						rt.MatchedDenies = append(rt.MatchedDenies, p)
						if firstDeny == nil {
							firstDeny = &Match{Assignment: a, Role: r.Name, Rule: p, Effect: EffectDeny}
						}
					}
				}
				for _, p := range r.Grants {
					if p.Matches(perm) {
						rt.MatchedGrants = append(rt.MatchedGrants, p)
						if firstAllow == nil {
							firstAllow = &Match{Assignment: a, Role: r.Name, Rule: p, Effect: EffectAllow}
						}
					}
				}
				at.Chain = append(at.Chain, rt)
			}
		}
		d.Trace = append(d.Trace, at)
	}

	switch {
	case firstDeny != nil:
		d.Effect, d.Decider = EffectDeny, firstDeny
	case firstAllow != nil:
		d.Allowed, d.Effect, d.Decider = true, EffectAllow, firstAllow
	}
	return d
}
