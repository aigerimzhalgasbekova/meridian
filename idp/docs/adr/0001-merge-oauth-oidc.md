# ADR 0001: One server for OAuth 2.0 and OpenID Connect

**Status:** Accepted · 2026-07-09

## Context

The brief listed "Centralized Login / OAuth 2.0 server" and "OpenID Connect
Provider" as two projects.

## Decision

Build them as one service, `idp`. Split out the session backend (the other half
of "centralized login") into a separate project, `sessiond`.

## Rationale

OpenID Connect is a profile *on top of* OAuth 2.0, not a parallel protocol. The
ID token, `userinfo`, and discovery are extensions to the same authorization-code
and token endpoints. Splitting them yields two servers that each implement half
of the same flow and must be kept byte-compatible — more surface, more drift,
less coherence. A reviewer evaluating protocol depth wants to see the whole flow
in one place.

The genuinely *different* engineering problem hiding inside "centralized login"
is distributed session management (cross-node invalidation, concurrency limits,
fixation defense). That earns its own project (`sessiond`) where it isn't
overshadowed by protocol surface.

## Consequences

- `idp` is the largest single service. It is kept navigable by strict internal
  package boundaries (`oauth`, `token`, `password`, `secrets`, `storage`,
  `server`), each independently testable.
- OIDC concerns (nonce, `auth_time`, `max_age`, claim release) live alongside
  the OAuth flow they extend, which is where they belong.
