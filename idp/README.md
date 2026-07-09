# idp — OAuth 2.0 / OpenID Connect Authorization Server

A multi-tenant authorization server built to survive a standards reviewer: the
full authorization-code + PKCE flow, refresh-token rotation with reuse
detection, device flow, client credentials, introspection, revocation, OIDC
discovery, userinfo, and dynamic client registration — with the deprecated,
dangerous grants (implicit, ROPC) deliberately absent.

Signing is delegated to [keysmith](../keysmith); this service owns protocol
correctness, not cryptography.

## Standards

| RFC / Spec | Where |
|------------|-------|
| RFC 6749 — OAuth 2.0 | `internal/server/token.go`, `authorize.go` |
| RFC 6750 — Bearer tokens | `endpoints.go` (userinfo `WWW-Authenticate`) |
| RFC 7636 — PKCE (S256 only) | `internal/oauth/pkce.go` |
| RFC 7662 — Introspection | `endpoints.go` |
| RFC 7009 — Revocation | `endpoints.go` |
| RFC 8414 + OIDC Discovery | `endpoints.go` (`handleDiscovery`) |
| RFC 8628 — Device flow | `device.go` |
| RFC 7591 — Dynamic client registration | `register.go` (admin-gated) |
| OIDC Core — ID tokens, userinfo, nonce, auth_time, max_age, consent | throughout |
| RFC 9700 — OAuth Security BCP | refresh rotation, exact redirect matching, PKCE-for-public, no implicit/ROPC |

Deliberate exclusions (see [ADR 0002](docs/adr/0002-no-implicit-no-ropc.md)):
implicit grant, resource-owner password grant. Their absence is a security
feature, not a gap.

## Security properties worth reviewing

- **Refresh-token reuse detection.** Tokens rotate on every use; presenting a
  rotated (or wrong-client, or lost-race) token revokes the entire token
  family. Proven under real concurrency in `concurrency_test.go`.
- **Authorization-code replay defense.** Codes are single-use; a replay revokes
  the refresh family the first redemption issued (RFC 9700 §4.5.3).
- **Open-redirect discipline.** No error reaches `redirect_uri` until both
  `client_id` and an *exactly matched* `redirect_uri` are validated; everything
  before that renders an error page. `return_to` on the login/consent forms is
  constrained to same-realm authorize/device paths.
- **User-enumeration resistance.** Login failures are uniform in body and in
  timing (unknown users are verified against a real decoy Argon2id hash).
- **Session fixation defense.** Login always mints a fresh session ID and never
  adopts one from the request.
- **CSRF.** Double-submit token on every state-changing form.
- **PKCE S256 only**; `plain` is rejected. Public clients must use PKCE.

## Architecture

```
internal/
  oauth/     protocol primitives: error vocabulary, scopes, PKCE — no I/O
  password/  Argon2id (OWASP params) + constant-time verify + rehash detection
  secrets/   opaque token generation + SHA-256 hashing + RFC 8628 user codes
  token/     access/ID/refresh token construction (ID+userinfo share claim logic)
  storage/   store interfaces + memory (tests/dev) + postgres (production)
  server/    HTTP handlers, login/consent/device UI, middleware, session, guard
cmd/idpd/    the daemon
```

Storage sits behind narrow interfaces. The atomic operations that make the
security properties hold — auth-code `Consume`, refresh `Rotate`, device
`SetStatus` — are single SQL statements in the Postgres store (their atomicity
is the database row lock; correct across many idp replicas) and mutex-guarded in
the memory store. Every flow is tested against the memory store with a real
in-process keysmith; the same suite runs against Postgres under `-tags integration`.

## Run it

```sh
# Dev: in-memory store, seeded "demo" realm, needs a keysmith running
KEYSMITH_DEV_MODE=1 KEYSMITH_SIGNER_TOKENS=dev-signer go run ../keysmith/cmd/keysmithd &
IDP_DEV_MODE=1 IDP_KEYSMITH_TOKEN=dev-signer IDP_REGISTRATION_TOKEN=dev-reg go run ./cmd/idpd
```

Seeded demo realm: user `alice` / `password123`; clients `web-app`
(confidential), `spa` (public/PKCE), `cli` (device), `service` (client
credentials). Discovery at `http://localhost:8080/realms/demo/.well-known/openid-configuration`.

## Tests

```sh
make test         # go test -race ./... (memory store + in-process keysmith)
make test-int     # adds -tags integration (needs TEST_DATABASE_URL)
```

The server suite in `internal/server` drives complete browser flows through a
cookie jar against a real keysmith: authorization code + consent, PKCE happy
and attack paths, refresh rotation + reuse detection (incl. a concurrency
test), device flow with poll pacing, introspection/revocation semantics,
discovery document shape, and dynamic registration.

## Docs

- [ADR 0001 — merge OAuth AS and OIDC provider](docs/adr/0001-merge-oauth-oidc.md)
- [ADR 0002 — no implicit, no ROPC](docs/adr/0002-no-implicit-no-ropc.md)
- [ADR 0003 — refresh rotation with family reuse detection](docs/adr/0003-refresh-rotation.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
