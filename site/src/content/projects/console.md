---
name: console
title: console
pitch: An RBAC control plane that never answers with a bare yes/no — every decision carries a full evaluation trace.
challenge: Authorization modeling — scoped roles with explicit denies, explainability as the product, and an API dog-fooded through its own engine.
tech: [Go, React, TypeScript, RBAC]
order: 7
---

## What it is

The Meridian admin console: a Go API and React SPA for managing users, roles, assignments, and sessions across the platform. Its signature feature is that `Check(subject, permission, scope)` returns a `Decision` recording exactly which assignment, which role in the inheritance chain, and which grant or deny rule produced the verdict — including the near-misses (assignments skipped for scope mismatch, roles that matched nothing), because "why was this denied" is only answerable if those are visible.

## Key design decisions

- **[ADR 0001 — RBAC with first-class explanation, not ABAC or ReBAC.](https://github.com/aikazzh/portfolio/blob/main/console/docs/adr/0001-rbac-with-explanation.md)** The domain is role-shaped: a small stable set of operations and job functions. ABAC's power buys nothing here and costs a policy language; ReBAC earns its complexity only for deep object graphs. Choosing the simpler model is what makes explanation affordable — in RBAC, the trace *is* the evaluation. Traces are contract, not log: tests assert on trace shape, the API returns them on 403s, the UI renders them.
- **[ADR 0002 — explicit deny overrides every allow.](https://github.com/aikazzh/portfolio/blob/main/console/docs/adr/0002-deny-overrides-allow.md)** No specificity ranking, no rule ordering: a deny anywhere in any matching chain vetoes every allow. Under deny-overrides, adding a grant can never silently defeat an existing restriction — the worst a mistake can do is deny too much, which is observable and safe. "A deny always wins" survives an incident review at 3am; it also enables the useful patterns: `users:*` grant + `users:delete` deny is one role, and a `suspended` role denying `*:*` instantly neutralizes a super-admin.
- **[ADR 0003 — scope on the assignment, not the role.](https://github.com/aikazzh/portfolio/blob/main/console/docs/adr/0003-scope-model.md)** `{subject, role, scope}` where scope is global or exactly one realm. One `realm-admin` role serves every realm. The write rules this produces are the whole tenancy boundary: role definitions demand *global* `roles:write` (a role a realm-admin authored would be assignable in other realms), while assignment writes are checked *at the scope being granted*.

## Dog-fooding

The console's own API is authorized by the same engine it administers. `POST /v1/roles` checks `roles:write` at global scope through `rbac.Check`; a denied admin receives the full decision trace in the 403 body. There is no privileged backdoor — if the model can't express an operation, the console can't perform it. Every mutation attempt, allowed or denied, lands in the audit trail.

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/console/THREAT_MODEL.md): the primary adversary is the authenticated-but-malicious admin. Inheritance cycles are rejected at role-definition time so evaluation never has to detect them; `*:read` (wildcard resource, concrete action) is rejected as an over-grant invitation; the dev HS256 verifier is called out as dev-grade *in the threat model itself* — a shared symmetric key means anyone who can verify can mint — with the production keysmith-JWKS Ed25519 verifier behind the same one-method interface. JSON bodies are capped at 1 MiB with unknown fields rejected; every response carries `nosniff`/`DENY`/`no-referrer`/`no-store` headers.

## Verified by

- `go test -race ./...` — **68 tests pass** (run 2026-07-10).
- Engine tests assert inheritance chains, wildcard-vs-exact matching, deny override across assignments (`TestDenyOverridesAllowAcrossAssignments`), scope isolation (`TestAssignmentScopeEnforcement`), cycle rejection, and the shape of explanation traces.
- API tests prove the dog-fooding: an operator cannot create roles, a realm-admin cannot act outside their realm, and denied attempts are audited.
- `make web` — TypeScript strict + Vite production build for the SPA.

## Code worth reading

- [`rbac/rbac.go`](https://github.com/aikazzh/portfolio/blob/main/console/rbac/rbac.go) — the whole engine: a pure library with zero I/O, where `Check` builds the trace as it evaluates.
- [`internal/server/`](https://github.com/aikazzh/portfolio/tree/main/console/internal/server) — every handler's first act is a `require*` check; the route map documents permission-per-route for review.
