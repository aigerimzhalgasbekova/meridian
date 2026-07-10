---
name: bridge
title: bridge
pitch: An SSO federation gateway — the RP side of OIDC implemented from scratch against live, occasionally-broken upstreams.
challenge: External-dependency resilience — correct discovery, state, nonce, PKCE, and ID-token verification against providers you don't operate, including the Entra tenanted-issuer sharp edge.
tech: [Go, OIDC RP, circuit breaker, Ed25519]
order: 5
---

## What it is

An identity broker: applications integrate against *one* relying party — bridge — and bridge federates to the upstream providers (Google, Microsoft Entra ID, anything OIDC). Apps receive a short-lived signed assertion with normalized claims at their exact registered callback. The RP side of OIDC is implemented from scratch on purpose; JWT/JWKS verification reuses [keysmith](/projects/keysmith/)'s `jose` package — no third-party OIDC client library.

## The architectural challenge

Upstream IdPs are dependencies bridge does not operate. When Microsoft is down, the failure mode to refuse is the slow one: every login holding a connection against a dead endpoint. Each provider gets a consecutive-failure circuit breaker (closed → open → half-open) around discovery, token exchange, and JWKS fetches; when open, `/login/{provider}` fails fast with a page listing healthy alternates. Cached JWKS are served up to **24 hours stale** during an outage — a public key doesn't go bad because the server hosting it is down — then verification fails closed, because unbounded staleness would make key revocation advisory. See [ADR 0002](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0002-breaker-and-stale-jwks.md).

## Key design decisions

- **[ADR 0001 — never match by email.](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0001-never-match-by-email.md)** Email matching is the classic federated account-takeover vector: an attacker with an account at provider B asserting the victim's email gets resolved to the victim's identity — no cryptography broken. Login matching is `(provider, subject)` only; email is a display attribute. Same email from a second provider yields a *separate* identity plus a visible linking offer, never an auto-merge.
- **Linking requires fresh auth to both sides.** The session's last upstream authentication must be under 5 minutes old *and* the provider being linked is authenticated within the link flow itself — so a stolen long-lived cookie cannot graft an attacker's account onto a victim.
- **[ADR 0003 — state, nonce, and PKCE with distinct jobs.](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0003-state-nonce-pkce.md)** State (HMAC-signed, provider-bound, 10-minute expiry, one-time by *consumption* — a signature alone can never provide replay protection) binds the callback to a login bridge started; nonce binds the signed ID token to the flow; the PKCE verifier never leaves the server.

## The Entra sharp edge

Entra's multi-tenant discovery declares its issuer as the literal template `https://login.microsoftonline.com/{tenantid}/v2.0`. Compare naively and you reject every valid token; skip the check and you accept tokens from **any tenant on Earth**. bridge substitutes the token's `tid` into the template — so `iss` and `tid` must agree — requires `tid` to exist, and optionally pins an allowed-tenant list. Covered by `TestEntraTenantedIssuer` (agree/disagree/missing/allowlist cases).

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/bridge/THREAT_MODEL.md): ID tokens are never accepted from the front channel — only from the code exchange bridge itself performs; the key set, never the token header, decides the verification algorithm; assertions go only to the exact registered app callback (no user-supplied redirect exists to abuse) and carry `aud` + a 2-minute TTL — a message, not a session; replayed callbacks are rejected uniformly.

## Verified by

- `go test -race ./...` — **56 tests pass** (run 2026-07-10; the fake in-process OIDC upstream in `internal/fakeidp` powers the suite and dev mode — no accounts needed).
- Named threat-model tests: `TestStateReplayRejected`, `TestTamperedStateRejected`, `TestEntraTenantedIssuer`, `TestEmailCollisionStaysUnlinked`, `TestLinkRequiresFreshAuth`, `TestBreakerOpensOnUpstreamFailure`, `TestJWKSStaleTolerance`, `TestFailFastLoginPage`, `TestAssertionDelivery`.

## Code worth reading

- [`internal/provider/`](https://github.com/aikazzh/portfolio/tree/main/bridge/internal/provider) — discovery with ETag caching, stale-tolerant JWKS with kid-miss refresh, full ID-token verification, Google + Entra presets.
- [`internal/relay/`](https://github.com/aikazzh/portfolio/tree/main/bridge/internal/relay) — the HMAC state parameter and one-time flow consumption.
- [`internal/health/`](https://github.com/aikazzh/portfolio/tree/main/bridge/internal/health) — the per-provider circuit breaker.
