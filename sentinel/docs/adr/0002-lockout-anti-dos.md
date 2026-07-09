# ADR 0002: Escalating lockout with a capped account dimension

**Status:** Accepted · 2026-07-09

## Context

Brute-force lockout has a classic failure mode: it hands attackers a
denial-of-service primitive. Anyone who knows a victim's username can fail
five logins on purpose and lock the victim out — repeatedly, forever, for
free. NIST SP 800-63B explicitly warns that lockout mechanisms must weigh
this abuse case.

## Decision

Track failures in two independent dimensions with different escalation caps:

- **Per-account:** 5 consecutive failures → 1 minute lock, doubling per
  lockout, **capped at 15 minutes**.
- **Per-IP:** same escalation, **capped at 24 hours**.

Both dimensions are always checked; a success that lands while either
dimension is locked does not reset counters.

## Rationale

- **Why two dimensions:** IP-only tracking misses a botnet focusing one
  victim (each bot under the IP threshold); account-only tracking misses one
  host spraying many accounts (a few attempts per account, under every
  account threshold). Each dimension covers the other's blind spot.
- **Why the account cap is low:** the account dimension is
  attacker-controlled — unbounded escalation there converts lockout into a
  victim-DoS weapon. 15 minutes caps the worst case at "victim inconvenienced",
  never "victim bricked", while still reducing an online-guessing attacker to
  ~20 guesses/hour/account.
- **Why the IP cap is high:** escalating the IP dimension only ever locks the
  attacker's own address. There is no victim to DoS.
- **Residual gap:** a distributed attacker can re-lock one account at the cap
  indefinitely. Longer lockouts don't fix that (they make the DoS worse); a
  different control does. `Tracker.ChallengeHook` is the seam: on repeated
  account lockouts, switch to CAPTCHA / step-up / notify-the-owner instead of
  more lockout. Sentinel's risk engine provides the step-up decision.
- **Timing safety:** `Check` does identical work whether or not the key is
  locked, and the API pushes callers toward one uniform "invalid credentials"
  response — a distinguishable locked-account response is a username oracle.

## Consequences

- A determined distributed attacker degrades one account to periodic
  15-minute windows; alerting via the hook is the mitigation, by design.
- In-memory state; a Redis hash per key (EXPIRE = FailWindow) is the
  documented multi-instance seam.
