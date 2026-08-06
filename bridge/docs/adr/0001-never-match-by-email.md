# ADR 0001: Match upstream logins by (provider, subject), never by email

## Status

Accepted.

## Context

When a federated login arrives, bridge must decide which local identity it
belongs to. The tempting rule is email: it's human-meaningful, both Google and
Entra assert it, and it makes the "same person, two providers" case merge
automatically.

It is also the classic federated account-takeover vector:

1. Alice signs up via provider A as `alice@example.com`.
2. `example.com` lapses, or Alice releases the address, or provider B simply
   doesn't verify email ownership. Mallory obtains an account at provider B
   asserting `email: alice@example.com`.
3. Mallory logs in to bridge via provider B. Email matching resolves her to
   Alice's identity. Mallory is now Alice everywhere bridge's assertions are
   trusted.

Nothing in step 2 requires breaking cryptography. The ID token Mallory
presents is *genuine* — provider B truthfully reports what its account claims
its email is. The flaw is treating an attribute one party asserts as an
identifier valid across all parties. Emails are mutable (most IdPs let holders
change them), sometimes unverified (`email_verified` exists precisely because
this is common), and re-assignable (corporate and consumer address recycling).

The `sub` claim, by contrast, is what OIDC Core §2 defines as the stable,
never-reassigned identifier — but only *within* one issuer.

## Decision

The one and only login-time matching rule is the pair `(provider, subject)`
(`directory.Store.IdentityByLink`). Email is stored as a display attribute.

Consequences we accept and design for:

- The same human arriving via two providers gets **two identities**. bridge
  surfaces the collision on the account page (`IdentitiesByEmail` exists for
  this hint and nothing else) and offers explicit linking.
- Linking is a deliberate act requiring fresh authentication to **both**
  sides: a live session whose last upstream auth is under 5 minutes old, plus
  a full auth-code flow to the provider being linked. Session possession alone
  is insufficient — a stolen cookie must not be able to attach an attacker's
  upstream account to the victim's identity (the reverse takeover).
- No auto-merge exists anywhere, even when emails match exactly and both are
  verified. `AddLink` refuses a `(provider, subject)` already linked anywhere.
- An email the upstream does not vouch for (`email_verified` absent or false)
  is **dropped at the callback** — not recorded on the identity and not put in
  the app-facing assertion. Refusing to *match* on an untrusted address while
  still forwarding it downstream, signed by bridge, would just move the
  takeover to any relying app that keys accounts on the `email` claim.
  Assertions carry an explicit `email_verified` so apps need not infer it.

## Alternatives considered

- **Match by verified email only (`email_verified: true`).** Still trusts
  every configured provider's verification policy and still breaks on address
  recycling. Rejected.
- **Auto-merge on collision with notification.** Converts a detection
  opportunity into an after-the-fact apology. Rejected.
