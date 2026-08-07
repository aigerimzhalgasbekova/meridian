# Threat model — console

Scope: the console API (`internal/server`), the rbac engine, the dev HS256 verifier,
and the SPA. The console is the platform's control plane: whoever controls it controls
authorization for everything, so it is modeled as a high-value target with
authenticated-but-malicious admins as the primary adversary.

## Assets

- The role/assignment database (tampering = privilege escalation everywhere).
- Admin bearer tokens.
- User PII (emails, names) and session metadata (IP, user agent).
- The audit trail (integrity is what makes incidents reconstructable).

## Trust boundaries

1. Internet → API (bearer JWT required on every `/v1` route).
2. API → rbac engine (every handler, no bypass path).
3. API → session backend / user store (interfaces; in-memory in dev).
4. Browser SPA → API (the SPA is untrusted rendering; all enforcement is server-side).

## Threats and mitigations

### Authentication

| Threat | Mitigation |
|---|---|
| Forged/tampered JWT | HMAC-SHA256 verified in constant time (`hmac.Equal`); `sub` and `exp` mandatory |
| Algorithm confusion (`alg: none`, RS256 swap) | `alg` header must equal `HS256` exactly; no negotiation from token input — negative-tested in `auth_test.go` |
| Expired-token replay | `exp` enforced against server clock |
| Token theft via logs | Tokens never logged; request log records subject-free method/path/status only |

The HS256 verifier is dev-grade by design: a shared symmetric key means anyone who can
verify can also mint. Production must wire the keysmith JWKS (Ed25519, kid-pinned)
verifier through the same one-method interface. This is documented, not hidden.

### Authorization

| Threat | Mitigation |
|---|---|
| Privilege escalation via role creation | `roles:write` demanded at **global** scope; realm-admins denied (tested) |
| Realm-admin escaping their realm | Assignment writes checked at the scope being granted; user/session ops checked at the target's realm (tested) |
| Reading another realm's privilege map | List routes filter results, not just the gate: `/v1/users` by realm, `/v1/assignments` by readable scope, `/v1/authz/explain` drops out-of-scope trace entries (tested) |
| Cross-realm target enumeration (403 vs 404 oracle) | The realm-derived scope forces lookup-before-check, so a miss answers 404 only to a caller authorized for *every* target: allowed at global **and** not carved out by a realm-scoped deny in any realm they hold (a global allow alone is not enough — deny > allow, and a realm assignment does not cover a global check, so a carve-out holder would 404 on a miss and 403 on a hit in that realm). Everyone else gets a 403 whose body names neither the scope nor the decision, so a miss and a cross-realm hit are byte-identical, and the probe is audited (tested). These three routes are the only ones that give up the explanation trace — it *is* the oracle here. **Residual**: `GET /v1/users/{id}/sessions` is a read, so its denials are not audited — a scan confined to that route leaves no trail |
| Deny bypass via a second role/assignment | Deny > allow across all assignments and chains (tested) |
| Inheritance cycle → evaluation hang | Cycles rejected at definition time; evaluation never detects, it assumes |
| Wildcard over-grant (`*:read`) | Pattern rejected at validation; queries must be concrete |
| Handler forgetting an authz check | Convention: every handler's first act is `require*`; the route map in `server.go` documents permission-per-route for review |
| Self-lockout (admin revokes own access) | Not prevented — deny-by-default is preferred over magic exemptions; recovery is a re-seed (dev) or DB-level fix (prod) |

### Audit

| Threat | Mitigation / residual risk |
|---|---|
| Denied attempts invisible | Every mutation appends its outcome — the denial at the gate, including probes at targets that do not exist. **Residual**: an *authorized* attempt that then fails appends nothing at all — a probe that 404s, a target that vanishes before the write, an unknown role (400), a built-in role deletion (409). Nothing happened, so the trail is silent; it records outcomes, not intents. A caller who is already authorized learns nothing from these that the read routes would not tell them |
| Trail says "allowed" for a mutation that never landed | The denial is recorded at the gate; the success only after the store reports the change landed, so `allowed: true` means it took effect — including when the target vanishes between the lookup and the write. Role writes carry their grants/denies in `detail` |
| Trail tampering | **Residual in dev**: in-memory slice, no integrity. Production seam is sentinel's hash-chained store |
| Trail exhaustion (memory) | Residual: unbounded slice in dev; acceptable for demo, bounded/offloaded in production |

### API hygiene

- JSON bodies capped at 1 MiB (`http.MaxBytesReader`), unknown fields rejected.
- Error envelope never echoes internals; store errors map to generic 500s.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store`, and a `Content-Security-Policy` on every
  response — API *and* SPA assets: `cmd/consoled` wraps the composed handler, because
  the SPA file server does not route through the API's middleware.
- Panics are recovered, logged with a request ID, and answered 500 without a stack. If
  the response was already committed the body is left intact rather than having an
  error envelope appended to it — the client keeps the status it saw.

### SPA

- No secrets at build time; token entered/selected at runtime, held in
  `localStorage`. Residual risk: XSS in the SPA could read it — mitigated by React's
  default escaping and zero use of `dangerouslySetInnerHTML`, with a restrictive CSP
  (`default-src 'self'`, no inline script/style, `object-src`/`base-uri`/
  `frame-ancestors 'none'`) behind it so source-code discipline is not the only
  control; residual risk accepted for an admin tool on a trusted origin.
- `/v1/dev/tokens` exists **only** when `CONSOLE_DEV_MODE=1`; it is the documented
  demo backdoor and must never be set in production.

## Explicit non-goals

- Rate limiting / brute-force lockout: sentinel's job, fronting the platform.
- Transport security: TLS terminates at the platform edge (ALB).
- Multi-node consistency: the in-memory engine is single-process; the Postgres seam
  carries the concurrency story in production.
