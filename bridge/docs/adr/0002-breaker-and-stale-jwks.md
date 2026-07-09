# ADR 0002: Circuit breakers per provider, bounded-stale JWKS

## Status

Accepted.

## Context

bridge's availability is hostage to identity providers it does not operate.
When an upstream degrades, the failure mode to refuse is the slow one: every
`/login/{provider}` holding a connection for a 10-second timeout against a
dead discovery or token endpoint, users staring at spinners, goroutines and
sockets piling up. An outage at one provider must not degrade logins through
the others, and must produce an *answer*, fast.

Separately: ID-token verification needs the provider's JWKS. If the JWKS
endpoint is down, do cached keys keep working, and for how long?

## Decision

**One three-state circuit breaker per provider** (`internal/health`) wraps
every network touch of that upstream — discovery, JWKS fetch, token exchange:

- *closed*: normal; consecutive failures counted.
- *open*: after 5 consecutive failures; all calls rejected immediately for a
  30s cooldown. `/login/{provider}` renders a fail-fast page listing the
  providers whose breakers are closed — "Microsoft is down, Google works" is a
  better answer than a spinner.
- *half-open*: after cooldown, exactly one probe is admitted (concurrent
  callers are rejected rather than stampeding a recovering upstream). Success
  closes; failure re-opens.

Consecutive-failure counting rather than a failure-rate window is deliberate:
bridge's upstream call volume is low and bursty (a discovery hit plus a token
exchange per login), so a rate window is starved of samples. Five in a row
from one upstream is unambiguous. `/healthz/providers` exposes the states.

**Caches degrade in order of risk:**

- *Discovery metadata*: cached per `Cache-Control`/ETag; served stale
  indefinitely on refresh failure. Endpoint URLs move rarely; a login that can
  proceed on 10-minute-old URLs should.
- *JWKS*: cached the same way, but staleness is **bounded at 24 hours**.
  Within the bound, verification keeps working through an outage — a public
  key does not become invalid because the server hosting it is unreachable.
  Past the bound we fail closed: a key rotated out after a compromise must
  eventually stop verifying, and 24h is the window we accept between "key
  revoked upstream" and "bridge stops honoring it". Unbounded staleness would
  make revocation advisory.
- *Kid-miss refresh*: a token signed by a `kid` absent from the cache triggers
  one forced JWKS refresh and a retry — upstreams rotate keys without notice,
  and a token newer than our cache is routine, not an attack. (One retry only;
  a genuinely unknown key cannot trigger refresh loops.)

## Alternatives considered

- **Retries with backoff instead of a breaker.** Retries help transient
  blips but make sustained outages *worse* — more load, longer user-visible
  latency. The breaker composes with the caller's single attempt.
- **Fail-open on JWKS (accept unverifiable tokens during outages).** Never.
  Availability of login through *other* providers is the outage story;
  unverified tokens are not.
