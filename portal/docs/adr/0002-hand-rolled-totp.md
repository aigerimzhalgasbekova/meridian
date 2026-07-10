# ADR 0002: Hand-rolled RFC 6238 TOTP

**Status:** Accepted · 2026-07-09

## Context

TOTP MFA needs HOTP (RFC 4226) truncation, the RFC 6238 time-step wrapper,
base32 secret encoding, and an `otpauth://` provisioning URI. npm offers
`otplib`, `speakeasy`, and friends.

## Decision

Implement it directly on `node:crypto`: ~60 lines for HOTP/TOTP/verify, ~35
for base32. Verify the implementation against the RFC 4226 Appendix D and
RFC 6238 Appendix B test vectors in CI.

## Rationale

- **The algorithm is small and frozen.** One HMAC, a dynamic-truncation
  offset, a modulus. It has not changed since 2011 and will not. A dependency
  here is surface without maintenance benefit.
- **The npm options are a poor trade.** `speakeasy` is unmaintained (last
  release 2017); `otplib` pulls a tree of packages for what is one screen of
  auditable stdlib code. For a security-focused codebase, reviewable beats
  imported.
- **Test vectors make correctness objective.** The RFCs publish expected
  outputs; the suite pins every one. That is stronger assurance than trusting
  a library's own tests.
- **The hard parts are policy, not math** — and libraries don't solve them:
  drift window (±1 step), replay defense (persist the last accepted time-step
  counter; never accept a counter ≤ it, even within the drift window),
  verify-to-activate enrollment, hashed single-use recovery codes. Those live
  in application code either way.

## Consequences

- SHA-1 only, 6 digits, 30-second steps — what every authenticator app ships.
  The `hotp()` signature accepts other digests/digit counts if ever needed.
- Code comparison uses `timingSafeEqual`; secrets are generated at 160 bits
  per RFC 4226's recommendation.
- We own any bug. Mitigated by the vector suite, drift/replay/malformed-input
  tests, and end-to-end enrollment + step-up tests through the HTTP API.
