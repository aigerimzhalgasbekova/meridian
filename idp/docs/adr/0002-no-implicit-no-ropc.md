# ADR 0002: No implicit grant, no resource-owner password grant

**Status:** Accepted · 2026-07-09

## Context

RFC 6749 defines the implicit grant (§4.2) and the resource-owner password
credentials grant (§4.3). A "complete" OAuth server might implement all four
grants from the original spec.

## Decision

Do not implement implicit or ROPC. Support authorization-code (+PKCE),
refresh-token, client-credentials, and device-code grants only.

## Rationale

RFC 9700 (OAuth 2.0 Security Best Current Practice) is explicit:

- **Implicit grant "SHOULD NOT be used."** It returns tokens in the URL
  fragment, exposing them to the browser history, referrer leakage, and
  injection. Authorization-code + PKCE supersedes it for exactly the clients
  (SPAs, native apps) implicit was meant for.
- **ROPC "MUST NOT be used."** It requires the client to handle the user's
  password directly, defeating the entire point of delegated authorization and
  making federation, MFA, and phishing-resistant auth impossible.

Implementing a grant the security BCP tells you to remove is not
completeness — it is a liability that a reviewer should, and would, flag. Their
absence is the correct, defensible position, and the discovery document
advertises only the supported grants so clients can't even attempt them.

## Consequences

- Clients that would have used ROPC (e.g. first-party mobile login) use the
  authorization-code flow with PKCE, or the device flow for input-constrained
  cases.
- The token endpoint returns `unsupported_grant_type` (or
  `unauthorized_client`) for `password`/`token` grant attempts, tested in
  `token_test.go`.
