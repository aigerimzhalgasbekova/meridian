# ADR 0002: Explicit deny overrides every allow

**Status:** Accepted — 2026-07-09

## Context

With wildcard grants and role inheritance, two rules can match one query with opposite
effects: a role grants `users:*` and denies `users:delete`; or a subject holds one
role that allows and another that denies. Some precedence rule must resolve the
conflict. The main candidates:

1. **Deny overrides** — any matching deny wins, regardless of source or specificity.
2. **Most-specific wins** — `users:delete` outranks `users:*`, whatever the effect.
3. **Order-dependent** — first matching rule wins (firewall-style).

## Decision

Fixed precedence: **explicit deny > allow > default deny**. A deny anywhere in any
scope-matching assignment's role chain vetoes every allow. There is no specificity
ranking and no rule ordering.

## Rationale

- **Fail closed under composition.** Roles are composed by inheritance and by multiple
  assignments, written by different admins at different times. Under deny-overrides,
  adding a grant can never silently defeat an existing restriction; the worst a
  mistake can do is deny too much, which is observable and safe. Under
  most-specific-wins, adding an innocuous-looking exact grant punches a hole through a
  wildcard deny — the dangerous direction.
- **Explainable in one sentence.** "A deny always wins" survives an incident review at
  3am. Specificity ranking requires defining specificity across wildcards, inheritance
  depth, and assignment order — three axes of tie-breaking nobody remembers under
  pressure. Order-dependence makes the answer depend on data layout, which is poison
  for an engine whose product is explanations.
- **Precedent.** AWS IAM, Azure RBAC deny assignments, and Kubernetes RBAC's
  aggregation all converge on explicit-deny-wins (or omit deny entirely); none rank by
  specificity.
- **It enables the useful pattern.** "Everything on users except delete" is one role:
  grant `users:*`, deny `users:delete`. A `suspended` role denying `*:*` instantly
  neutralizes a super-admin without touching their other assignments — tested in
  `TestDenyOverridesAllowAcrossAssignments`.

## Consequences

- There is no "allow override" escape hatch: un-denying requires removing the deny
  rule or the assignment carrying it. This is intended friction.
- Default is deny: a subject with no matching rule gets `default_deny`, and the trace
  still records every near-miss so the denial is diagnosable.
