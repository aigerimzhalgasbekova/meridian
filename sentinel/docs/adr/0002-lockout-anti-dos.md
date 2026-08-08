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

- **Per-account:** 5 **consecutive** failures → 1 minute lock, doubling per
  lockout, **capped at 15 minutes**. The counter is not cleared by the passage
  of time — a paced attacker would simply stay under any counting window.
- **Per-IP:** 50 failures (10× the account threshold) **within one FailWindow
  (1h)** → the same doubling ladder, **capped at 24 hours**. This dimension
  *is* windowed: a whole quiet window zeroes the count, and a whole quiet
  window with no lock in force zeroes the escalation too.

Both dimensions are always checked. A success resets the **account** dimension
only, and only when neither dimension is locked: a success during a lockout
must not unlock, and clearing the IP counter would let a sprayer wipe it by
logging into an account they control. The IP count is bounded by the window
roll instead, not by success.

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
- **Why the IP threshold is 10× and windowed:** an IP aggregates failures
  across every account behind it, and — unlike the account counter — no success
  clears it. A shared egress (office NAT, CGNAT, a mobile carrier) would
  otherwise accumulate ordinary fumbled passwords until it locked every user
  behind it with no attacker present. The higher threshold and the hourly roll
  are what keep that from happening.
- **Why the IP cap is high:** an IP lock is *mostly* the attacker's own
  address, but "there is no victim to DoS" is not true — a shared egress has
  real users behind it. **Open question, accepted for now:** 24h is only
  reachable by an address sustaining 50 failures/hour across several hours,
  which no ordinary office NAT does; the roll resets a merely noisy one. If a
  real CGNAT ever trips it, the fix is to lower `IPCap` or exempt known egress
  ranges — not to restore the success-based reset, which is the sprayer's
  escape hatch.
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
