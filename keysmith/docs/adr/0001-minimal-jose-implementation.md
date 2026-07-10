# ADR 0001: Implement a minimal JOSE layer instead of importing a library

**Status:** Accepted · 2026-07-09

## Context

Every service in the platform signs or verifies JWTs. The Go ecosystem has
mature JOSE libraries (`go-jose`, `golang-jwt`). The default engineering
instinct — "never write your own crypto" — points at importing one.

## Decision

Implement JWS compact serialization, JWT claims validation, and JWK/JWKS
handling in `keysmith/jose` (~700 lines), using **only** stdlib crypto
primitives (`crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`). No cryptographic
algorithm is implemented here — signing and verification are one-call stdlib
operations. What this package owns is the *protocol* layer: parsing,
serialization, and policy.

## Rationale

"Don't roll your own crypto" applies to primitives, not to protocol plumbing.
The JOSE protocol layer is precisely where most real-world JWT vulnerabilities
have lived, and general-purpose libraries must carry the flexible surface that
enables them:

- `alg: none` acceptance (CVE-2015-9235 and descendants)
- RS256→HS256 key confusion (CVE-2016-5431) — possible only because the
  library lets token input choose the algorithm family
- embedded `jwk` header trust (CVE-2018-0114)
- `jku`/`x5u` URL dereference and `crit` downgrade handling bugs

Owning the layer lets us delete those degrees of freedom *structurally*:

- Three algorithms exist; HMAC does not; `none` does not.
- The verifier's pinned key set decides the algorithm; the token's header is
  checked for consistency, never obeyed.
- `jwk`, `jku`, `x5u`, `x5c`, `crit`, and any unknown header parameter are
  hard rejections.
- Only base64url-without-padding parses; only 3-segment compact form parses.

The test suite encodes each historical CVE pattern as a permanent regression
test (`jose/jws_test.go: TestKnownAttackPatterns`).

## Consequences

- We accept maintenance of ~700 lines of security-critical parsing code, with
  the mitigation that the surface is frozen and heavily tested.
- Interop is deliberately narrower than full JOSE (no JWE, no nested JWTs, no
  RSA-PSS). Downstream services must live within this profile — which is the
  point.
- If a future integration genuinely requires JWE or PS256, the decision is to
  extend this package with the same allowlist discipline, not to swap in a
  general-purpose library.
