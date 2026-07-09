# idp Threat Model

Scope: the authorization server — its endpoints, login/consent UI, token
lifecycle, and multi-tenant realm isolation.

## Assets

| Asset | Impact if compromised |
|-------|----------------------|
| User credentials (Argon2id hashes) | Account takeover |
| Authorization codes | Token theft if combined with a redirect leak |
| Refresh tokens | Sustained access until detection |
| Login sessions | Impersonation within the session window |
| Client secrets | Client impersonation |
| Realm isolation | Cross-tenant identity confusion |

## Trust boundaries

1. **Browser ↔ authorize/login/consent.** Untrusted user agent. Defenses:
   exact redirect-URI matching, CSRF double-submit, session fixation reset,
   security headers (CSP `default-src 'none'`, `frame-ancestors 'none'`,
   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`), no query logging.
2. **Client ↔ token/introspect/revoke.** Authenticated (client_secret_basic /
   _post, or PKCE for public clients). Constant-time secret comparison.
3. **idp ↔ keysmith.** Signer token; access tokens verified locally against a
   cached JWKS.
4. **idp ↔ storage.** Secrets stored only as hashes; atomic single-use ops.

## Top abuse cases and mitigations

| # | Attack | Mitigation |
|---|--------|-----------|
| 1 | Open redirect via crafted `redirect_uri` | Exact match against registered set; error page (not redirect) until validated |
| 2 | Authorization-code interception | PKCE (S256) required for public clients; code single-use, 60s TTL, bound to client + redirect_uri |
| 3 | Code replay | `used` flag flipped atomically; replay revokes the issued refresh family |
| 4 | Refresh-token theft | Rotation + family reuse detection; wrong-client presentation kills the family |
| 5 | Concurrent refresh double-spend | Atomic conditional UPDATE; at most one winner (concurrency-tested) |
| 6 | Credential stuffing / brute force | Per-user and per-IP failure windows (LocalGuard; sentinel in full platform) |
| 7 | User enumeration | Uniform login errors + decoy-hash timing equalization |
| 8 | Session fixation | Fresh session ID on every login; old cookie invalidated |
| 9 | CSRF on login/consent/device | Double-submit token, `SameSite=Lax` cookies |
| 10 | Token substitution via alg confusion | keysmith's allowlist JOSE (no HS/none/embedded-jwk) |
| 11 | Cross-realm token use | Per-realm issuer in every token; userinfo/introspection check issuer + audience |
| 12 | Introspection/revocation as a validity oracle | Confidential-caller-only introspection; revocation always 200; coarse errors |
| 13 | Device user-code brute force | 8-char high-entropy code, 10-min TTL, one-shot approval, poll pacing (`slow_down`) |
| 14 | Open dynamic registration abuse | Registration gated by an initial access token; https-only redirect URIs (loopback excepted) |

## Residual risks (accepted)

- **LocalGuard is per-process.** Multi-replica brute-force protection requires
  sentinel (shared state). Documented; the interface (`LoginGuard`) is the seam.
- **Access tokens are not individually revocable.** Contained by short TTL, not
  revocation. This is the standard stateless-JWT trade-off.
- **A client racing its own refresh** can trip reuse detection and be logged
  out. Accepted: it fails toward revocation.
- **No built-in MFA in idp.** MFA enrollment/verification lives in `portal`;
  step-up would extend the login flow. Out of scope for this service.
