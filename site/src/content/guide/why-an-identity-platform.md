---
title: Why build an identity platform
chapter: 1
summary: The scope, the decomposition into interlocking projects, and what makes each one architecturally distinct.
---

Most portfolio projects are apps with a login screen. This one is the login screen — and everything behind it: keys, tokens, sessions, federation, rate limits, account recovery, and the authorization layer that decides who may administer all of it.

Meridian is a standards-aligned IAM platform of the kind a mid-size company would run to centralize authentication. It was designed as eight interlocking projects (seven services plus the deployment platform), each a standalone, reviewable codebase. The organizing principle, stated in the [design document](https://github.com/aikazzh/portfolio/blob/main/docs/design/2026-07-09-meridian-platform-design.md) before any code existed:

> Every project must answer a different engineering question. Not eight CRUD apps with login screens — eight distinct problem shapes.

## The decomposition

| Project | The engineering question |
|---|---|
| [keysmith](/projects/keysmith/) | Cryptographic key lifecycle: how do you rotate signing keys with zero downtime, and store them so a leaked file is useless? |
| [idp](/projects/idp/) | Protocol correctness: can an OAuth 2.0 / OIDC authorization server survive RFC scrutiny — including its concurrency edge cases? |
| [sessiond](/projects/sessiond/) | Distributed state: how does a revoked session die on every node, provably, when your invalidation transport is fire-and-forget? |
| [sentinel](/projects/sentinel/) | Stream decisions: rate limiting and lockout that can't be weaponized, plus an audit trail that detects its own tampering |
| [bridge](/projects/bridge/) | External-dependency resilience: correct RP-side OIDC against upstream IdPs you don't operate — including when they're down |
| [portal](/projects/portal/) | Async workflow security: the account-recovery flows attackers actually target, driven by a Postgres job queue |
| [console](/projects/console/) | Authorization modeling: RBAC where every decision can explain itself |

The eighth project — `platform`: Terraform, CI/CD, the one-command local stack — is not yet deployed — validated and `terraform plan`-clean against a real AWS account, but unapplied; [chapter 9](/guide/running-it/) covers its design and exactly what's pending.

## Decisions made before writing code

The original brief listed candidate projects and granted latitude to swap or merge. Three restructurings mattered:

**"Centralized Login" and "OIDC Provider" merged into one `idp`.** OIDC is a profile *on top of* OAuth 2.0 — the ID token, userinfo, and discovery extend the same authorization-code and token endpoints. Splitting them yields two servers each implementing half of the same flow, kept byte-compatible by hope ([ADR](https://github.com/aikazzh/portfolio/blob/main/idp/docs/adr/0001-merge-oauth-oidc.md)). The genuinely different problem hiding inside "centralized login" — distributed session management — became `sessiond`, where it isn't overshadowed by protocol surface.

**Key management was promoted to project #1.** Every other service consumes keysmith's signing or verification surface. Building it first forces an honest interface instead of a retrofitted one. [Chapter 2](/guide/keys-before-tokens/) is the full argument.

**Federation stayed separate from the IdP.** Building SSO into `idp` would have tangled two unrelated problems: protocol correctness (idp's) and external-dependency resilience — what happens when Microsoft is down (bridge's).

## Cross-cutting rules

A few decisions hold everywhere, and they're the ones that shape how the code reads:

- **Go 1.26, stdlib-first.** The auth services use `net/http` with the 1.22+ pattern router; no web framework. In security-critical code, fewer dependencies mean a smaller attack surface and nothing hidden from review — middleware, routing, and graceful shutdown are written out and tested, not imported.
- **Polyglot where the language is honestly the better tool.** `portal` is TypeScript end to end; `sentinel`'s compliance tooling is stdlib-only Python, because a compliance auditor should be able to verify the audit chain without a Go toolchain.
- **HTTP + JSON over well-defined APIs. No shared database, no shared structs.** Each service also runs standalone with its dependencies faked, so each repo is independently reviewable.
- **Testing without Docker.** Every storage dependency sits behind a narrow interface with a real implementation and a test double (an in-memory Postgres-shaped store, miniredis). Full-stack integration tests against real Postgres exist behind a `-tags integration` build tag. The dev machine may not have a Docker daemon; the test suite must still prove correctness.
- **Every project ships a `THREAT_MODEL.md` and ADRs** for the decisions a reviewer would question. The threat models are STRIDE-lite — assets, trust boundaries, abuse cases, mitigations — and, importantly, they document the *accepted* risks rather than pretending none exist.

## How to read this guide

Chapters 2–8 walk the seven services in dependency order — the same order they were built, because dependencies flow backward only (idp consumes keysmith, never the reverse). Each chapter focuses on the one architectural idea that project exists to demonstrate, quotes the real code, and links the ADR where the trade-offs are argued properly. Chapter 9 covers deployment; chapter 10 is the honest retrospective — including the bugs.

Everything here is checkable: the claims link to files in the [monorepo](https://github.com/aikazzh/portfolio), and the "verified by" sections on the project pages cite test runs from this machine, not aspirations.
