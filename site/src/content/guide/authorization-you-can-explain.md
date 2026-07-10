---
title: Authorization you can explain
chapter: 8
summary: console — RBAC with decision traces as the contract, deny-overrides precedence, and an API dog-fooded through its own engine.
---

When an admin is denied, the operational question is always "why?" — and in most systems, answering it means a human re-deriving the policy evaluation by hand, because the authorization library returned a boolean. [console](/projects/console/), Meridian's control plane, is built around the opposite premise: **the explanation is the product**. Its `rbac.Check` never answers with a bare yes/no.

## The model, sized to the domain

[ADR 0001](https://github.com/aigerimzhalgasbekova/meridian/blob/main/console/docs/adr/0001-rbac-with-explanation.md) weighs RBAC against ABAC and ReBAC and picks RBAC deliberately. Console administration has a small, stable set of operations and job functions; ABAC's power buys nothing here and costs a policy language — parsing, evaluation semantics, and a whole class of misconfiguration. ReBAC (Zanzibar-style) earns its complexity when permissions follow deep object graphs; the console's only relationship is "user belongs to realm", which a one-field `Scope` expresses.

The insight worth keeping: **choosing the simpler model is what makes explainability affordable.** RBAC evaluation is a flat walk over assignments and inheritance chains — the trace *is* the evaluation. An honest ABAC explanation is a policy-language interpreter trace; few systems ship one because it's hard.

So: permissions are `resource:action` with wildcard actions (`users:*`) and the full wildcard (`*:*`) — but `*:read` is rejected, because a wildcard resource with a concrete action invites accidental over-grants. Roles bundle grants and explicit denies and extend at most one parent, with cycles rejected at definition time so evaluation never has to detect them. Assignments bind subject → role at a scope: global, or exactly one realm.

## Deny overrides, and why not specificity

Wildcards plus inheritance means two rules can match one query with opposite effects. [ADR 0002](https://github.com/aigerimzhalgasbekova/meridian/blob/main/console/docs/adr/0002-deny-overrides-allow.md) fixes the precedence:

```
explicit deny > allow > default deny
```

No specificity ranking, no rule ordering. A deny anywhere in any scope-matching assignment's chain vetoes every allow — an exact `users:delete` allow loses to a wildcard `users:*` deny. The rationale is about failure direction under composition: roles are written by different admins at different times, and under deny-overrides, adding a grant can never silently defeat an existing restriction — the worst a mistake can do is deny too much, which is observable and safe. Under most-specific-wins, an innocuous-looking exact grant punches a hole through a wildcard deny: the dangerous direction. And "a deny always wins" survives an incident review at 3am, which is more than can be said for specificity ranking across wildcards, inheritance depth, and assignment order. AWS IAM, Azure RBAC deny assignments, and Kubernetes RBAC converge on the same answer.

It also enables the useful patterns: "everything on users except delete" is one role (grant `users:*`, deny `users:delete`), and a `suspended` role denying `*:*` instantly neutralizes a super-admin without touching their other assignments.

## The trace is a contract

`Check(subject, permission, scope)` returns a `Decision` that records everything considered — including assignments skipped for scope mismatch and roles that matched nothing — because "why was this denied" is only answerable if the near-misses are visible. The engine ([`rbac/rbac.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/console/rbac/rbac.go), a pure library with zero I/O) builds the trace as it evaluates:

```go
at := AssignmentTrace{Assignment: a, ScopeMatch: a.Scope.covers(scope)}
if at.ScopeMatch {
    for _, r := range e.chain(a.Role) {
        rt := RoleTrace{Role: r.Name}
        for _, p := range r.Denies {
            if p.Matches(perm) {
                rt.MatchedDenies = append(rt.MatchedDenies, p)
                ...
```

Traces are contract, not log: tests assert on trace shape (chain order, matched rules, scope-mismatch records), every 403 carries the full decision in its body, and the SPA's "Explain access" panel renders it. If the trace ever lied about the decision, tests would fail.

## Scope on the assignment, and the two write rules

[ADR 0003](https://github.com/aigerimzhalgasbekova/meridian/blob/main/console/docs/adr/0003-scope-model.md): scope lives on the assignment (`{subject, role, scope}`), so one `realm-admin` role serves every realm and the role catalog never explodes combinatorially. The tenancy boundary then reduces to two write rules:

- **Role definitions are global objects**, so `roles:write` is checked at *global* scope. A realm-admin cannot mint roles — a role they authored would be assignable in other realms, exceeding their authority.
- **Assignment writes are checked at the scope being granted.** This single check is the whole boundary: alice, realm-admin of engineering, can assign `viewer` at `realm:engineering`; assigning at `realm:finance` or globally is denied. Delegation within your own realm is allowed by design; escalation to global is impossible because no realm-scoped check covers it.

## Dog-fooding: no privileged backdoor

The console's own API is authorized by the same engine it administers. `POST /v1/roles` goes through `rbac.Check` like everything else; a denied admin gets the trace in the 403 body. There is no backdoor path — if the model can't express an operation, the console can't perform it, including against its operator. Self-lockout (an admin revoking their own access) is deliberately *not* prevented: deny-by-default beats magic exemptions, and recovery is a documented re-seed. Every mutation attempt, allowed or denied, lands in the audit trail.

The [threat model](https://github.com/aigerimzhalgasbekova/meridian/blob/main/console/THREAT_MODEL.md) models the control plane honestly: the primary adversary is the authenticated-but-malicious admin, and the dev-grade HS256 verifier is called out *in the threat model* (a shared symmetric key means anyone who can verify can also mint), with the production keysmith-JWKS Ed25519 verifier behind the same one-method interface.

Try it locally: `make run-dev` seeds two realms and six personas; act as `alice` (engineering realm-admin), try to disable a finance user, and read the trace in the 403.

**Verified by:** 68 tests under `-race` — inheritance chains, wildcard-vs-exact matching, deny override across assignments, scope isolation, cycle rejection, trace shape, and the dog-fooding negatives (an operator cannot create roles; a realm-admin cannot act outside their realm; denials are audited).
