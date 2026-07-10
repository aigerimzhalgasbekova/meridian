---
title: Federating identity
chapter: 6
summary: bridge — the sharp edges of RP-side OIDC, why you never match accounts by email, and circuit breakers for IdPs you don't operate.
---

Everyone implements the OP side of OIDC in tutorials; the RP side — being the *client* of Google, Microsoft Entra ID, and whatever else the enterprise brings — is where the sharp edges live. [bridge](/projects/bridge/) is an identity broker: applications integrate against one relying party, and bridge federates upstream, delivering short-lived signed assertions with normalized claims. The RP flow is implemented from scratch on purpose (reusing keysmith's `jose` for the cryptography); correct discovery, state, nonce, PKCE, and ID-token verification against a live, occasionally-broken upstream **is** the showcase.

## Three anti-forgery values, three different jobs

The authorization-code flow's anti-forgery values are commonly confused with each other; [ADR 0003](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0003-state-nonce-pkce.md) keeps their jobs distinct:

- **state** binds the callback to a login bridge actually started (CSRF defense on the redirect). bridge's state is `base64url(JSON{flow id, provider, exp})` + an HMAC-SHA256 signature — unforgeable, expiring (10 min), and bound to the provider it was minted for, so a state for `/callback/google` can't replay against `/callback/entra`.
- **nonce** binds the *signed ID token* to this login. It's required to match inside the token at verification, so a genuine token spliced in from any other flow fails.
- **PKCE verifier** binds the code redemption to the initiator. It never leaves the server; only its S256 challenge goes upstream.

The subtle point: **one-time use comes from consumption, not signatures.** Verifying a state atomically deletes its flow record; a replayed callback finds nothing. A signature check alone can never provide replay protection — signatures verify as many times as you like. Both mechanisms exist because they defend against different things, and the check order in `Consume` is deliberate: signature first (until it passes, every payload byte is attacker-controlled), then expiry, then one-time use.

## The Entra tenanted-issuer sharp edge

The best example of "the RP side is where the bugs are." Entra's multi-tenant discovery document declares its issuer as the *literal template string*:

```
https://login.microsoftonline.com/{tenantid}/v2.0
```

Compare `iss` naively against that and you reject every valid token. And the tempting workaround — skip issuer validation, the signature checked out, ship it — means you accept tokens from **any tenant on Earth**: any organization's Entra tenant can mint a token your verifier accepts. Real-world RP implementations have made exactly this mistake.

bridge's handling: substitute the token's `tid` claim into the template and require exact match — so `iss` and `tid` must agree — require `tid` to *exist* when the issuer is templated (missing is a rejection, not a fallback), and optionally pin an `AllowedTenants` list. `TestEntraTenantedIssuer` covers the agree/disagree/missing/allowlist matrix. Discovery documents must also declare the exact configured issuer (RFC 8414 §3.3) or the provider refuses to initialize.

## Never match by email

When a federated login arrives, which local identity does it belong to? Matching by email is tempting — it's human-meaningful and merges the "same person, two providers" case automatically. It is also the classic federated account-takeover vector ([ADR 0001](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0001-never-match-by-email.md)): Mallory obtains an account at provider B asserting `alice@example.com` (a lapsed domain, a released address, a provider that doesn't verify email), logs in, and email matching resolves her to Alice's identity everywhere bridge's assertions are trusted. Nothing in that attack breaks cryptography — the token is *genuine*. The flaw is treating an attribute one party asserts as an identifier valid across all parties.

So the one and only matching rule is `(provider, subject)` — OIDC's `sub` is the stable, never-reassigned identifier, but only within one issuer. Email is a display attribute. The consequences are designed for, not suffered: the same human via two providers gets two identities plus a visible linking offer (never an auto-merge, even with verified matching emails), and **linking requires fresh authentication to both sides** — a live session whose last upstream auth is under 5 minutes old, plus a full auth-code flow to the provider being linked. A stolen long-lived cookie cannot graft an attacker's upstream account onto a victim's identity.

## When Microsoft is down

Upstream IdPs are dependencies bridge doesn't operate, and the failure mode to refuse is the slow one: every `/login/{provider}` holding a connection for a 10-second timeout against a dead endpoint, users staring at spinners, sockets piling up. [ADR 0002](https://github.com/aikazzh/portfolio/blob/main/bridge/docs/adr/0002-breaker-and-stale-jwks.md):

- **One three-state circuit breaker per provider** (closed → open → half-open) wraps every network touch: discovery, token exchange, JWKS. Five consecutive failures open it; when open, the login page fails fast and lists the providers whose breakers are closed — "Microsoft is down, Google works" beats a spinner. Consecutive-failure counting (not a rate window) is deliberate: bridge's upstream call volume is low and bursty, so a rate window is starved of samples.
- **Caches degrade in order of risk.** Discovery metadata is served stale indefinitely — endpoint URLs move rarely. JWKS staleness is **bounded at 24 hours**: within the bound, verification keeps working through an outage (a public key doesn't go bad because its server is unreachable); past it, verification fails closed, because a key rotated out after a compromise must eventually stop verifying. Unbounded staleness would make revocation advisory.
- **Kid-miss refresh, once.** A token signed by an unknown `kid` triggers exactly one forced JWKS refresh and retry — upstreams rotate keys without notice — but only one, so a genuinely unknown key can't drive refresh loops.

And the line that should be tattooed somewhere: fail-open on JWKS — accepting unverifiable tokens during an outage — was considered and rejected with a one-word rationale in the ADR: *never*. Availability-through-other-providers is the outage story; unverified tokens are not.

**Verified by:** 56 tests under `-race`, driven by an in-process fake OIDC upstream (`internal/fakeidp`) — the same fake that powers `make run-dev`, so you can watch the email-collision and linking flows in a browser with no cloud accounts.
