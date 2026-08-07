# bridge — SSO Federation Gateway

An identity broker: applications integrate against *one* Relying Party —
bridge — and bridge federates to the upstream identity providers (Google,
Microsoft Entra ID, anything OIDC). The RP side of OIDC is implemented from
scratch on purpose; correct discovery, state, nonce, PKCE, and ID-token
verification against a live, occasionally-broken upstream **is** the showcase.
JWT/JWKS verification reuses [keysmith](../keysmith)'s `jose` package; no
third-party OIDC client library is involved.

## Why a broker

Without one, every app re-implements the RP flow — and re-makes its mistakes:
skipped issuer checks, unbound nonces, email-based account matching. With one:

- **One integration point.** Apps receive a short-lived signed assertion with
  normalized claims (`sub` = stable bridge identity, `email`, `name`, `idp`,
  `amr`) at their exact registered callback. Register them with
  `BRIDGE_APPS=id=https://app.example.com/callback,…` (malformed or non-https
  entries fail startup, not the first `?app=` request) and verify against
  `GET /.well-known/jwks.json`. Adding an upstream provider is a bridge config
  change; no app changes.
- **One identity across providers.** JIT provisioning creates a local identity
  on first login; explicit linking ties multiple upstream accounts to it.
  Matching is by `(provider, subject)` — never by email
  ([ADR 0001](docs/adr/0001-never-match-by-email.md)).
- **One place to absorb upstream outages.** Per-provider circuit breakers,
  bounded-stale JWKS caching, and a fail-fast login page that offers healthy
  alternates ([ADR 0002](docs/adr/0002-breaker-and-stale-jwks.md)).

## The flow

```
Browser          bridge                      upstream IdP
  │  GET /login/{p}  │                            │
  │─────────────────►│  mint flow: state (HMAC),  │
  │                  │  nonce, PKCE verifier      │
  │  302 ────────────┤                            │
  │  authorize?...state&nonce&code_challenge ────►│  user authenticates
  │◄──────────────────────────── 302 ?code&state ─┤
  │  GET /callback/{p}?code&state                 │
  │─────────────────►│  consume state (one-time)  │
  │                  │  POST /token (code+verifier) ─►
  │                  │◄─ id_token ────────────────┤
  │                  │  verify: sig (JWKS), iss,  │
  │                  │  aud, exp, nonce, alg      │
  │                  │  match (provider,subject)  │
  │◄─ 302 app callback?assertion=JWT              │
```

Details of the state/nonce/PKCE design:
[ADR 0003](docs/adr/0003-state-nonce-pkce.md). Attack coverage:
[THREAT_MODEL.md](THREAT_MODEL.md).

## Security properties worth reviewing

- **Full RP-side ID-token verification** (`internal/provider`): signature via
  keysmith/jose (allowlist RS256/ES256, mandatory `kid`, `none` impossible by
  construction), exact issuer, audience contains our client_id, expiry, and
  nonce bound to the specific login flow.
- **The Entra tenanted-issuer sharp edge, handled.** Entra's multi-tenant
  discovery declares its issuer as the literal template
  `https://login.microsoftonline.com/{tenantid}/v2.0`. Compare naively and you
  reject every valid token; skip the check and you accept tokens from **any**
  tenant on Earth. bridge substitutes the token's `tid` into the template and
  requires `tid` to exist; for the multi-tenant endpoints (`common`,
  `organizations`, `consumers`) it also *requires* a non-empty allowed-tenant
  list, refusing to start without one. Covered by `TestEntraTenantedIssuer`.
- **No account takeover via email reuse.** Login matching is
  `(provider, subject)` only. Same email from a second provider yields a
  *separate* identity and a visible collision notice — never an auto-merge.
  (Linking is the pre-emptive remedy, available until that second provider is
  first used to sign in; after that the pair is spoken for and nothing merges
  it.)
- **Linking requires fresh auth to both sides.** The current session's last
  upstream authentication must be recent (5 min), and the provider being
  linked is authenticated within the link flow itself. A stolen long-lived
  cookie cannot graft an attacker's account onto a victim.
- **State is one-time, signed, and expiring**; nonce and PKCE verifier never
  leave the server. Replayed callbacks are rejected.
- **Assertions go only to exact registered app callbacks** — there is no
  app-supplied redirect parameter to abuse.

## Resilience

Upstream IdPs are dependencies bridge does not operate. Each provider gets a
consecutive-failure circuit breaker (closed → open → half-open) around
discovery, token exchange, and JWKS fetches. When open, `/login/{provider}`
fails fast with a page listing healthy alternates instead of hanging users on
a dead upstream. Cached JWKS are served up to 24h stale during an outage —
public keys don't go bad because the server hosting them is down — then
verification fails closed. `/healthz/providers` exposes breaker states.

## Architecture

```
internal/
  provider/   upstream registry: discovery (ETag cache), JWKS (stale-tolerant,
              kid-miss refresh), token exchange, ID-token verification,
              Google + Entra presets
  relay/      login-flow state: HMAC state parameter, nonce, PKCE, one-time use
  directory/  local identities + provider links (Store interface, in-memory impl)
  health/     per-provider circuit breaker
  server/     HTTP handlers, demo UI, sessions, app-facing assertion signing
  fakeidp/    in-process fake OIDC upstream (tests + dev mode)
cmd/bridged/  the daemon
```

The assertion signer is an injected interface; dev and tests use an ephemeral
local Ed25519 key, production plugs in a keysmith-backed signer (the shape of
`keysmith/client.Client.Sign` matches).

## Run it

```
make run-dev    # BRIDGE_DEV_MODE=1: built-in fake upstreams, no accounts needed
```

Open http://127.0.0.1:8083 — sign in via the built-in upstream, then **link
the second upstream from the account page** (linking must happen before the
second provider is ever used to sign in; once it has its own identity, the
`(provider, subject)` pair is spoken for and linking 409s by design — see
[ADR 0001](docs/adr/0001-never-match-by-email.md)). Sign in via the second
upstream from a fresh browser profile to see the email-collision handling
instead. Then hit `/?app=demo` to watch an assertion get delivered.

```
make test       # go test ./... -race
```
