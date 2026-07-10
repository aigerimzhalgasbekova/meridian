# console — RBAC control plane that explains itself

The Meridian admin console: a Go API and React SPA for managing users, roles,
assignments, and sessions across the platform. Its signature feature is that the
authorization engine never answers with a bare yes/no — **every decision carries a
trace** of exactly which assignment, which role in the inheritance chain, and which
grant or deny rule produced the verdict.

## The model

- **Permission** — `resource:action` (`users:read`). Rules may use a wildcard action
  (`users:*`) or the full wildcard (`*:*`); `*:read` is rejected because a wildcard
  resource with a concrete action invites accidental over-grants. Queries must be concrete.
- **Role** — a named bundle of grants and optional explicit denies, extending at most
  one parent (single inheritance; cycles rejected when the role is defined, so
  evaluation never has to detect them).
- **Assignment** — subject → role at a **scope**: global, or one realm. A realm-scoped
  assignment confers nothing outside its realm — this is what makes "admin of
  engineering, nobody in finance" a one-line policy.
- **Built-in catalog** — `viewer` → `operator` → `realm-admin` (an inheritance chain),
  plus `super-admin` (`*:*`). Built-ins are immutable; custom roles can extend them.

### Precedence

```
explicit deny  >  allow  >  default deny
```

A deny anywhere in any matching assignment's role chain vetoes every allow.
Specificity never outranks effect: an exact `users:delete` allow loses to a wildcard
`users:*` deny, and vice versa. With no matching rule at all, the answer is deny.
See [ADR 0002](docs/adr/0002-deny-overrides-allow.md) for why.

### Explanation as a first-class result

`Check(subject, permission, scope)` returns a `Decision`:

```json
{
  "subject": "alice", "permission": "users:write", "scope": {"realm": "engineering"},
  "allowed": true, "effect": "allow",
  "decider": {
    "assignment": {"subject": "alice", "role": "realm-admin", "scope": {"realm": "engineering"}},
    "role": "operator", "rule": "users:write", "effect": "allow"
  },
  "trace": [
    {"assignment": {"role": "realm-admin", "scope": {"realm": "engineering"}}, "scope_match": true,
     "chain": [{"role": "realm-admin"}, {"role": "operator", "matched_grants": ["users:write"]}, {"role": "viewer"}]},
    {"assignment": {"role": "viewer", "scope": {"realm": "finance"}}, "scope_match": false}
  ]
}
```

The trace records everything considered — including assignments skipped for scope
mismatch and roles that matched nothing — because "why was this denied" is only
answerable if the near-misses are visible. The UI's **Explain access** panel and every
403 response render this structure; the engine's tests assert on traces, not just
verdicts ([ADR 0001](docs/adr/0001-rbac-with-explanation.md)).

## Dog-fooding

The console's own API is authorized by the same engine it administers. `POST
/v1/roles` checks `roles:write` at global scope through `rbac.Check`; a denied admin
receives the full decision trace in the 403 body. There is no privileged backdoor
path — if the model can't express an operation, the console can't perform it. This is
deliberate: the control plane is the first consumer of its own product.

Every mutation attempt — allowed or denied — lands in the audit trail (`GET /v1/audit`).

## API

All `/v1` routes require `Authorization: Bearer <JWT>`. Errors use one envelope:
`{"error": "<code>", "message": "..."}`, plus `"decision"` on authorization denials.

| Route | Permission (scope) |
|---|---|
| `GET /v1/permissions` | `permissions:read` (any held scope) |
| `GET /v1/roles`, `GET /v1/roles/{name}` | `roles:read` (any held scope) |
| `POST/PUT/DELETE /v1/roles…` | `roles:write` (**global** — roles are global objects) |
| `GET /v1/assignments` | `assignments:read` (any held scope) |
| `POST /v1/assignments`, `POST /v1/assignments/revoke` | `assignments:write` (**at the assignment's scope**) |
| `GET /v1/authz/explain` | `authz:explain` (any held scope) |
| `GET /v1/users` | `users:read` (list filtered to readable realms) |
| `POST /v1/users/{id}/disable\|enable` | `users:write` (target user's realm) |
| `GET /v1/users/{id}/sessions` | `sessions:read` (target user's realm) |
| `POST /v1/sessions/{id}/revoke` | `sessions:revoke` (session owner's realm) |
| `GET /v1/audit` | `audit:read` (global) |

Scope rules worth noting ([ADR 0003](docs/adr/0003-scope-model.md)): role definitions
demand global `roles:write` (a realm-admin cannot mint roles), while assignment writes
are checked *at the scope being granted* — the single check that confines a
realm-admin to their realm.

## Running locally

```sh
make run-dev        # API + built SPA on :8085, seeded demo world
cd web && npm run dev   # or: Vite dev server proxying /v1 to :8085
```

Dev mode seeds two realms (engineering, finance), four users with live sessions, six
personas (`root`, `olivia` the operator, `alice`/`frank` realm-admins, `vera` the
viewer, `sam` on a deny-carve-out `support` role), and exposes `GET /v1/dev/tokens`
with pre-minted tokens — the SPA's "act as" picker uses it. Try acting as `alice` and
disabling a finance user: the 403 shows you the trace.

## Seams (in-memory now, documented swap)

- **Verifier** (`internal/auth`): HS256 static-key JWT for dev/tests; production wires
  a keysmith-JWKS Ed25519 verifier — the interface is one method.
- **UserStore**: in-memory map; Postgres is a mechanical swap (single table).
- **SessionProvider**: in-memory fake; production is an HTTP client against sessiond.
- **AuditLog**: in-memory slice; production appends to sentinel's hash-chained store.

## Tests

```sh
make test   # go test -race ./... — engine, API authz, auth negative cases
make web    # npm install + tsc strict + vite build
```

The engine tests assert inheritance chains, wildcard-vs-exact matching, deny override
(including across assignments), scope isolation, cycle rejection, and the shape of
explanation traces. The API tests prove the dog-fooding: an operator cannot create
roles, a realm-admin cannot act outside their realm, and denied attempts are audited.

## Docs

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, abuse cases,
  residual risk
- [ADR 0001](docs/adr/0001-rbac-with-explanation.md) — RBAC with an explanation trace
- [ADR 0002](docs/adr/0002-deny-overrides-allow.md) — deny overrides allow
- [ADR 0003](docs/adr/0003-scope-model.md) — the scope model
