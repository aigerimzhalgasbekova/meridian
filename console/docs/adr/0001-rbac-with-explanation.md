# ADR 0001: RBAC with first-class explanation, not ABAC or ReBAC

**Status:** Accepted — 2026-07-09

## Context

The console needs an authorization model for platform administration. The candidates:

- **RBAC** — subjects hold roles; roles bundle permissions.
- **ABAC** — policies over arbitrary attributes of subject/resource/environment
  (`department == "eng" && time < 18:00`).
- **ReBAC** — permissions derived from a relationship graph (Zanzibar-style
  `user:alice#member@group:eng`).

Separately: most authorization libraries return a boolean. When an admin is denied,
the operational question is always "why?" — and answering it usually means a human
re-deriving the policy evaluation by hand.

## Decision

RBAC with scoped assignments, single inheritance, explicit denies — and a `Decision`
struct that records the full evaluation trace as the *return value* of every check.

## Rationale

- **The domain is role-shaped.** Console administration has a small, stable set of
  operations and a small set of job functions (view, operate, administer-a-realm,
  administer-everything). ABAC's power buys nothing here and costs a policy language:
  parsing, evaluation semantics, and an entire class of misconfiguration. ReBAC earns
  its complexity when permissions follow deep object graphs (documents in folders in
  projects); the console's only relationship is "user belongs to realm", which a
  one-field `Scope` expresses.
- **Explainability is the product, not a debug aid.** A trace that shows *which
  assignment → which role in the chain → which rule* decided the outcome turns every
  denial into a self-service answer. This is cheap in RBAC precisely because
  evaluation is a flat walk over assignments and chains — the trace is the evaluation.
  Under ABAC, an honest explanation is a policy-language interpreter trace; few
  systems ship one because it's hard. Choosing the simpler model is what makes the
  explanation feature affordable.
- **Traces are contract, not log.** Tests assert on trace shape (chain order, matched
  rules, scope-mismatch records), the API returns traces on 403s, and the UI renders
  them. If the trace ever lied about the decision, tests fail.

## Consequences

- Attribute-style conditions (time-of-day, IP) cannot be expressed; if ever needed,
  they arrive as a new rule type with trace support, not as a bolted-on DSL.
- Single inheritance (see the cycle-rejection logic in `rbac.DefineRole`) keeps chains
  linear and traces readable; role composition beyond one parent must be modeled as
  multiple assignments.
- The engine is a pure library with zero I/O, so any Meridian service could embed it.
