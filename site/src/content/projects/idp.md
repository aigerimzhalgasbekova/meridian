---
name: idp
title: idp
pitch: A multi-tenant OAuth 2.0 / OpenID Connect authorization server built to survive a standards reviewer.
challenge: Protocol correctness at scale — eight RFCs implemented exactly, with the concurrency-sensitive security properties proven by single-statement database atomicity.
tech: [Go, Postgres, OAuth 2.0, OIDC, Argon2id]
order: 2
---

## What it is

The flagship: a multi-tenant authorization server implementing the authorization-code + PKCE flow, refresh-token rotation with family reuse detection, device flow, client credentials, introspection, revocation, OIDC discovery, userinfo, and admin-gated dynamic client registration. Signing is delegated to [keysmith](/projects/keysmith/); idp owns protocol correctness, not cryptography.

## Standards coverage

RFC 6749 (OAuth 2.0 core, exact §5.2 error semantics), RFC 6750 (Bearer + `WWW-Authenticate`), RFC 7636 (PKCE, S256 only), RFC 7662 (introspection), RFC 7009 (revocation), RFC 8414 + OIDC Discovery, RFC 8628 (device flow), RFC 7591 (dynamic registration), OIDC Core, and RFC 9700 (OAuth Security BCP). The deprecated grants — implicit and ROPC — are deliberately absent; per [ADR 0002](https://github.com/aikazzh/portfolio/blob/main/idp/docs/adr/0002-no-implicit-no-ropc.md), their absence is a security feature the discovery document advertises, not a gap.

## Key design decisions

- **[ADR 0001 — one server for OAuth and OIDC.](https://github.com/aikazzh/portfolio/blob/main/idp/docs/adr/0001-merge-oauth-oidc.md)** OIDC is a profile *on top of* OAuth 2.0; splitting them produces two half-servers that must stay byte-compatible. The genuinely different problem hiding inside "centralized login" — distributed session state — became its own project, [sessiond](/projects/sessiond/).
- **[ADR 0003 — refresh rotation with family reuse detection.](https://github.com/aikazzh/portfolio/blob/main/idp/docs/adr/0003-refresh-rotation.md)** Refresh tokens are opaque 256-bit values stored only as SHA-256 hashes, rotated on every use. Presenting a rotated token — the signature of leak-and-replay — revokes the entire family, as does wrong-client presentation, a disabled user, or losing a concurrent-redemption race.
- **Atomicity by single SQL statement.** The operations the security properties depend on — auth-code `Consume`, refresh `Rotate`, device `SetStatus` — are single conditional statements in the Postgres store, so correctness holds across many idp replicas via the database row lock rather than application locks:

```sql
UPDATE refresh_tokens SET rotated_at=$3
 WHERE realm_name=$1 AND token_hash=$2
   AND rotated_at IS NULL AND revoked=false
```

A concurrent second redemption updates zero rows and is rejected — at most one winner, no second successor ever issued ([`internal/storage/postgres/stores.go`](https://github.com/aikazzh/portfolio/blob/main/idp/internal/storage/postgres/stores.go)).

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/idp/THREAT_MODEL.md): no error reaches `redirect_uri` until both `client_id` and an exactly-matched `redirect_uri` are validated (open-redirect discipline); login failures are uniform in body *and* timing — unknown users are verified against a real decoy Argon2id hash; login always mints a fresh session ID (fixation defense); CSRF double-submit on every state-changing form; per-realm issuers in every token so cross-realm token use fails; device-flow user codes are high-entropy, one-shot, and poll-paced with `slow_down`.

## Verified by

- `go test -race ./...` — **98 tests pass** (run 2026-07-10; memory store + a real in-process keysmith).
- The server suite drives complete browser flows through a cookie jar: authorization code + consent, PKCE happy and attack paths, refresh rotation + reuse detection **including a 12-way concurrent redemption test** asserting at most one winner and family death, device flow with poll pacing, introspection/revocation semantics, discovery document shape, dynamic registration.
- The same suite runs against real Postgres under `-tags integration`.

## Code worth reading

- [`internal/server/token.go`](https://github.com/aikazzh/portfolio/blob/main/idp/internal/server/token.go) — the token endpoint and RFC 6749 §5.2 error semantics.
- [`internal/storage/postgres/stores.go`](https://github.com/aikazzh/portfolio/blob/main/idp/internal/storage/postgres/stores.go) — atomic `Rotate`/`Consume` as single conditional statements.
- [`internal/server/concurrency_test.go`](https://github.com/aikazzh/portfolio/blob/main/idp/internal/server/concurrency_test.go) — reuse detection under real concurrency.
- [`internal/oauth/pkce.go`](https://github.com/aikazzh/portfolio/blob/main/idp/internal/oauth/pkce.go) — PKCE, S256 only.
