# bridge — Threat Model

Scope: the SSO federation gateway — RP-side OIDC against upstream IdPs, JIT
provisioning and linking in the local directory, app-facing assertion
delivery, and the demo UI session. Cryptographic verification primitives are
in keysmith's threat model; this document covers how bridge uses them and what
bridge adds.

Assets: local identities and their provider links; app-facing assertions (a
forged or misdirected one is authentication bypass at every relying app);
in-flight login state (nonce, PKCE verifier); upstream client secrets.

## Trust boundaries

1. **Browser → bridge** — hostile. Every query parameter, cookie, and path
   value is attacker-controlled.
2. **bridge → upstream IdP** — semi-trusted. We trust a *configured* upstream
   to assert its own users correctly, but not the network path, not its
   availability, and — critically — not one upstream's claims about
   *identifiers governed by another* (email).
3. **bridge → relying app** — the assertion is the boundary; the app trusts
   its signature and claims.

## Threats and mitigations

### T1. Login CSRF / flow forgery

Attacker delivers a callback URL to the victim's browser (forced login to the
attacker's account) or forges a state.

- State parameter is HMAC-SHA256-signed and expires (10 min); an unsigned or
  tampered state is rejected before anything else is looked at.
- State is bound to the provider it was minted for.
- One-time consumption: the flow record is atomically deleted on first use;
  replays get a uniform error. Tests: `TestStateReplayRejected`,
  `TestTamperedStateRejected`. Design: ADR 0003.

### T2. ID-token injection / replay

Attacker obtains a genuine token (their own login, a leaked log) and splices
it into the victim's flow.

- Nonce: every flow mints a fresh CSPRNG nonce, sent upstream, required to
  match inside the *signed* token at verification. A token from any other flow
  fails (`ErrNonceMismatch`).
- Tokens are never accepted from the front channel at all — only from the
  code exchange bridge itself performs.

### T3. Authorization-code interception

Code leaks via redirect logs, referer, or a malicious app on the device.

- PKCE S256 on every flow: the verifier never leaves bridge's memory, so a
  captured code cannot be redeemed by anyone else.
- Exchange also sends the client secret (confidential client) — two
  independent proofs.

### T4. Token forgery / algorithm abuse

`alg: none`, HMAC key-confusion, attacker-supplied JWKS.

- keysmith/jose is allowlist-only: bridge accepts RS256/ES256 from upstreams,
  the *key set* (never the token header) decides the algorithm, `kid` is
  mandatory. JWKS come only from the discovery document's `jwks_uri`, which
  itself comes only from the configured/validated discovery URL.
- Tests: `tampered token rejected`, `token signed by unpublished key rejected`.

### T5. Issuer confusion — the Entra sharp edge

A token from tenant X presented where tenant Y (or a fixed issuer) was
expected; or an RP that skipped issuer validation because Entra's template
issuer made it awkward.

- Exact issuer match always. For templated (multi-tenant Entra) issuers, the
  expected value is the template with the token's `tid` substituted — so `iss`
  and `tid` must agree — and `AllowedTenants` can pin the tenant set. A
  missing `tid` on a templated issuer is a rejection, not a fallback.
- Discovery documents must declare the exact configured issuer (RFC 8414
  §3.3) or the provider refuses to initialize its metadata.
- Tests: `TestEntraTenantedIssuer` (agree/disagree/missing/allowlist),
  `wrong issuer rejected`, `issuer mismatch in discovery rejected`.

### T6. Account takeover via email reuse

Attacker controls an account at provider B asserting the victim's email.

- Login matching is `(provider, subject)` only; email is a display attribute.
  The attacker gets a fresh, empty identity. ADR 0001,
  `TestEmailCollisionStaysUnlinked`.

### T7. Hostile linking (session-riding)

Attacker with a stolen session cookie links their upstream account to the
victim's identity, gaining permanent access that survives password changes.

- Linking demands the session's last upstream authentication be under 5
  minutes old, *and* a full fresh auth-code flow to the provider being linked.
  A cookie alone starts nothing. The link callback re-checks freshness (the
  flow may outlive it). Tests: `TestLinkRequiresFreshAuth`,
  `TestLinkingAlreadyLinkedAccountRejected`.

### T8. Assertion misdelivery / open redirect

Attacker steers the post-login redirect to capture the assertion.

- No user-supplied redirect exists on the app side: assertions go to the
  exact `CallbackURL` registered in configuration for the requested `app` id,
  and unknown app ids are rejected before the flow starts. Test:
  `TestAssertionDelivery` (exact-URL check).

### T9. Assertion forgery / replay at the app

- Assertions are signed (Ed25519 locally; keysmith-backed in production) with
  `aud` set to the specific app and a 2-minute TTL — a message, not a session.
  Apps must verify signature, `iss`, `aud`, `exp` (the demo verifier in the
  test suite does exactly this).

### T10. Upstream outage as denial of service

A dead upstream ties up connections and blocks all logins.

- Per-provider circuit breakers fail fast and the login UI offers healthy
  alternates; JWKS staleness is tolerated for 24h then fails closed;
  `/healthz/providers` exposes state. ADR 0002, `TestFailFastLoginPage`,
  `TestBreakerOpensOnUpstreamFailure`, `TestJWKSStaleTolerance`.

### T11. Session fixation / theft (demo UI)

- Session IDs are 256-bit CSPRNG values minted server-side on every login —
  never adopted from a request. Cookies are HttpOnly, SameSite=Lax, Secure
  outside dev mode. Logout deletes server-side state, not just the cookie.

## Accepted risks / non-goals

- **In-memory stores** (directory, sessions, flows) — dev/test scope; the
  `directory.Store` interface is the seam for Postgres, sessiond for sessions.
- **No upstream logout propagation** (OIDC front/back-channel logout):
  bridge's logout ends bridge's session only.
- **Compromised upstream IdP** is out of scope by definition: a provider that
  lies about its own subjects defeats any RP. Blast radius is bounded per
  provider by the (provider, subject) rule and Entra tenant pinning.
- **HMAC key and client secrets via env** — deployment concern; rotate by
  restart. Flows are 10-minute-lived, so key rotation cost is one wave of
  restarted logins.
