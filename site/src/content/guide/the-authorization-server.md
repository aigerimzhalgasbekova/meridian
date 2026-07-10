---
title: The authorization server
chapter: 3
summary: idp — the RFC map, refresh-family reuse detection, single-statement atomicity, and the html/template escaping bug.
---

[idp](/projects/idp/) is the flagship: a multi-tenant OAuth 2.0 / OpenID Connect authorization server built to survive a standards reviewer. This chapter covers the three things that make it interesting — the RFC discipline, the reuse-detection design, and how its security properties survive concurrency — plus one instructive bug.

## The RFC map

The coverage: RFC 6749 (core grants, with exact §5.2 error semantics), 6750 (bearer usage and `WWW-Authenticate`), 7636 (PKCE, S256 only — `plain` is rejected), 7662 (introspection), 7009 (revocation), 8414 + OIDC Discovery (per-realm metadata), 8628 (device flow), 7591 (dynamic registration, admin-gated), OIDC Core (ID tokens, userinfo, nonce, `auth_time`, `max_age`, consent), and RFC 9700, the OAuth 2.0 Security BCP.

Just as important is what's absent. The implicit grant ("SHOULD NOT be used" — tokens in URL fragments leak via history and referrers) and the resource-owner password grant ("MUST NOT be used" — the client handling the user's password defeats delegated authorization entirely) are deliberately not implemented ([ADR 0002](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/docs/adr/0002-no-implicit-no-ropc.md)). Implementing a grant the security BCP tells you to remove isn't completeness; it's a liability a reviewer should flag. The discovery document advertises only the supported grants, so clients can't even attempt the others.

## Refresh families and reuse detection

Refresh tokens are long-lived credentials; if one leaks, the attacker mints access tokens until it expires. idp's containment ([ADR 0003](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/docs/adr/0003-refresh-rotation.md)):

- Tokens are opaque 256-bit random values, stored only as SHA-256 hashes, **rotated on every use**.
- All generations descended from one authorization share a `family_id`, whose absolute lifetime is fixed at first issuance — rotation never extends it.
- Presenting an already-rotated token — the signature of leak-and-replay — **revokes the entire family**. So does wrong-client presentation, a disabled owning user, or losing a concurrent-redemption race.

Rotation alone isn't enough: without reuse detection, an attacker who uses the stolen token *before* the legitimate client silently takes over the family. With it, any reuse becomes a detectable, contained event — the legitimate client's next refresh fails, signalling compromise, and nothing from the family remains valid. The accepted trade-off: a client racing itself (two tabs) can trip detection and get logged out. Rare, and it fails toward revocation, not token survival.

## Atomicity as a single SQL statement

Here's the part that makes the property hold in production rather than just in a diagram. The security-critical operations — auth-code `Consume`, refresh `Rotate`, device `SetStatus` — must be atomic across many idp replicas. idp doesn't use application locks or advisory locks; each is a single conditional statement, so the atomicity *is* the database row lock:

```sql
UPDATE refresh_tokens SET rotated_at=$3
 WHERE realm_name=$1 AND token_hash=$2
   AND rotated_at IS NULL AND revoked=false
```

A concurrent second redemption matches zero rows — the store distinguishes "not there" from "already rotated" and returns `ErrConsumed`, which the server treats as reuse and kills the family. `concurrency_test.go` fires 12 simultaneous redemptions of one token and asserts at most one succeeds. The memory store used in tests implements the same contract with a mutex, and the whole server suite runs against real Postgres under `-tags integration`.

The rest of the security posture follows the same "uniform and exact" style: no error reaches `redirect_uri` until both `client_id` and an exactly-matched `redirect_uri` validate (before that, you get an error page, never a redirect); login failures are uniform in body and timing — unknown usernames are verified against a real decoy Argon2id hash; every login mints a fresh session ID; every state-changing form carries a CSRF double-submit token.

## The escaping bug: test what a browser sends

The most instructive bug in idp's history wasn't in the server — it was in the tests, and it's a lesson worth a section.

The server suite drives complete browser flows: fetch the login page, scrape the form, post it back, follow redirects through consent to the authorization code. The harness extracted `return_to` and the CSRF token from the rendered HTML with a regex and posted the captured values back.

The problem: `return_to` is a URL with query parameters, rendered into an HTML attribute by Go's `html/template` — which correctly entity-escapes it, turning `&` into `&amp;`. The regex captured the *escaped* form, and the tests submitted `return_to=/realms/test/authorize?client_id=web-app&amp;redirect_uri=...` — a value no browser would ever send, because browsers HTML-decode attribute values before form submission. The tests were exercising a request flow that doesn't exist in reality, and failing (or worse, passing) for the wrong reasons.

The fix is two lines in the harness, with the reasoning in the comment ([`testenv_test.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/internal/server/testenv_test.go)):

```go
// A browser HTML-decodes attribute values before submitting them.
return e.postForm("/realms/test/login", url.Values{
    "csrf_token": {html.UnescapeString(csrf[1])},
    "return_to":  {html.UnescapeString(ret[1])},
    ...
})
```

The general lesson: when you test a browser-mediated flow below the level of a real browser, you are responsible for reproducing what the browser does — decoding, cookie policy, redirect handling. A test harness that scrapes rendered HTML is emulating a user agent, and it has to emulate it *correctly*, or your tests verify a protocol nobody speaks. This class of bug is invisible in code review because both the template and the regex look right in isolation.

## What to read

[`internal/server/token.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/internal/server/token.go) for the §5.2 error discipline; [`internal/storage/postgres/stores.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/internal/storage/postgres/stores.go) for the single-statement stores; the [threat model](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/THREAT_MODEL.md) for the full 14-row abuse-case table.

**Verified by:** 98 tests under `-race` against the memory store with a real in-process keysmith; the same flows against Postgres under `-tags integration`.
