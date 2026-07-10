# Meridian — an Identity & Access Management Platform

**Status:** Approved (autonomous build, full creative control granted)
**Date:** 2026-07-09
**Author:** Claude (concept & execution)

## 1. Vision

Meridian is a portfolio of eight interlocking projects — seven services plus the
platform that runs them, with the site alongside — that together form a realistic,
standards-aligned IAM platform — the kind of system a mid-size company would run to
centralize authentication, sessions, federation, and access control. Each project is a
standalone, reviewable codebase with its own signature architectural challenge; together
they compose into one working stack you can bring up locally with a single command and
deploy to AWS with Terraform.

The organizing principle: **every project must answer a different engineering question.**
Not eight CRUD apps with login screens — eight distinct problem shapes:

| # | Project | Signature challenge |
|---|---------|--------------------|
| 1 | `keysmith` | Cryptographic key lifecycle: zero-downtime rotation, envelope encryption, a hardened minimal JOSE layer |
| 2 | `idp` | Protocol correctness at scale: a multi-tenant OAuth 2.0 / OIDC authorization server that survives RFC scrutiny |
| 3 | `sessiond` | Distributed state: server-side sessions with cross-node invalidation, concurrency limits, fixation defense |
| 4 | `sentinel` | High-throughput stream decisions: distributed rate limiting, brute-force lockout, risk scoring, tamper-evident audit |
| 5 | `bridge` | External-dependency resilience: SSO federation with Google/Entra ID, JIT provisioning, account linking, IdP-outage fallbacks |
| 6 | `portal` | Async workflow security: self-service password reset / MFA enrollment with a Postgres-backed job queue (TypeScript) |
| 7 | `console` | Authorization modeling: RBAC control plane that can *explain* every permission decision (Go API + React) |
| 8 | `platform` | Infrastructure as a product: Terraform for AWS, CI/CD with security gates, one-command local stack, observability |

Plus `site/` — the portfolio site with the `/guide` engineering walkthrough.

## 2. What was asked vs. what I'm building

The brief listed eight candidate projects and granted latitude to swap or merge. Changes I made, and why:

- **Merged "Centralized Login" and "OIDC Provider" into `idp`**, because OIDC *is* an
  OAuth 2.0 profile — splitting them produces two half-servers. The session-backend half
  of "Centralized Login" becomes its own project (`sessiond`) with a genuinely different
  challenge (distributed state, not protocol compliance).
- **Promoted key management (`keysmith`) to the first build** — every other service
  consumes its signing or verification surface, and building it first forces an honest
  interface instead of a retrofitted one.
- **Kept SSO integration (`bridge`) separate from `idp`** rather than building federation
  into the IdP, to isolate the resilience problem (what happens when Microsoft is down?)
  from the protocol problem.
- **`portal` is deliberately TypeScript** and `sentinel`'s compliance reporting is
  deliberately Python — polyglot where the language is honestly the better tool, per the brief.

## 3. Architecture

```
                                   ┌────────────────────┐
        ┌───────────────┐          │  bridge (Go)       │───► Google / Entra ID
        │  site (Astro) │          │  SSO federation    │
        │  + /guide     │          └─────────┬──────────┘
        └───────────────┘                    │ federated identities (JIT)
                                             ▼
┌──────────────┐   OIDC/OAuth2    ┌────────────────────┐   sign/verify   ┌───────────────┐
│ portal (TS)  │◄────────────────►│  idp (Go)          │◄───────────────►│ keysmith (Go) │
│ self-service │                  │  OAuth2/OIDC AS    │                 │ keys + JOSE   │
└──────┬───────┘                  │  multi-tenant      │                 └───────────────┘
       │                          └───┬──────────┬─────┘
       │ jobs (pg queue)              │          │ session create/check
       ▼                              │          ▼
┌──────────────┐                      │   ┌────────────────────┐
│ Postgres     │                      │   │ sessiond (Go)      │◄── Redis (pub/sub
└──────────────┘                      │   │ distributed sessions│        invalidation)
                                      │   └────────────────────┘
       rate-limit / risk checks       ▼
┌──────────────┐  decision API  ┌────────────────────┐        ┌───────────────┐
│ console (Go+ │◄──────────────►│ sentinel (Go)      │───────►│ audit chain   │
│ React) RBAC  │                │ limits/risk/audit  │        │ (hash-linked) │
└──────────────┘                └────────────────────┘        └───────────────┘
```

Integration contract: services talk **HTTP + JSON over well-defined APIs** (no shared
database, no shared structs). Each service also ships as a Go library where embedding is
the realistic deployment mode (keysmith's JOSE layer, sentinel's limiter). Every service
runs standalone with its dependencies faked, so each repo is independently reviewable.

## 4. Technology decisions

- **Go 1.26, stdlib-first.** The auth servers use `net/http` with the 1.22+ pattern
  router, `pgx` for Postgres, `go-redis` where Redis is intrinsic. No web framework:
  in security-critical code, fewer dependencies mean smaller attack surface and nothing
  hidden from review. This is an explicit showcase choice — middleware, routing, and
  graceful shutdown are written out and tested, not imported.
- **Hand-built minimal JOSE in `keysmith`** using stdlib crypto (Ed25519/ECDSA/RSA),
  with an allowlist-only algorithm policy: no `none`, no `alg` negotiation from token
  input, no embedded-JWK trust, mandatory `kid` resolution against a pinned key set.
  Rationale: JWS compact serialization is small enough to implement verifiably, and
  owning it eliminates entire vulnerability classes (algorithm confusion, key smuggling)
  by construction — and demonstrates exactly the cryptographic literacy this portfolio
  is meant to prove. The test suite includes negative tests derived from known JOSE CVE patterns.
- **Postgres as system of record** (users, clients, tokens-hashes, audit); **Redis** only
  where its data model is the point (sessions, rate-limit state). Portal's job queue is
  Postgres `FOR UPDATE SKIP LOCKED` — no queue infrastructure for a service that already
  has Postgres.
- **Testing without Docker:** every storage dependency sits behind a narrow interface
  with a real implementation and a test double (in-memory Postgres-shaped store,
  `miniredis`). Full-stack integration tests against real Postgres/Redis exist behind a
  `//go:build integration` tag and run in CI and docker-compose. Rationale: the dev
  machine may not have a Docker daemon; the test suite must still prove correctness.
- **AWS** as the cloud target: ECS Fargate (services), RDS Postgres, ElastiCache Redis,
  ALB + ACM, SES (portal email), S3+CloudFront (site), CloudWatch + X-Ray via ADOT for
  observability — native tooling per the brief, no self-hosted observability stack.
  Terraform ≥1.10 with per-environment stacks and remote state.
- **Frontends:** React + Vite (portal, console), Astro (site). TypeScript strict mode.

## 5. Standards matrix (idp)

| RFC / Spec | Coverage |
|------------|----------|
| RFC 6749 (OAuth 2.0) | Authorization code, client credentials, refresh; exact §5.2 error semantics |
| RFC 6750 (Bearer) | Token usage + `WWW-Authenticate` error responses |
| RFC 7636 (PKCE) | Required for public clients, `S256` only |
| RFC 8628 (Device flow) | Full device authorization grant |
| RFC 7662 (Introspection) | Authenticated introspection endpoint |
| RFC 7009 (Revocation) | Token + token-family revocation |
| RFC 8414 / OIDC Discovery | Per-realm metadata documents |
| OIDC Core | ID tokens, `userinfo`, nonce, `auth_time`, consent |
| RFC 7591 (Dynamic client registration) | Admin-gated implementation |
| RFC 9700 (OAuth 2.0 Security BCP) | Refresh rotation + reuse detection, exact redirect URI matching, no implicit/ROPC |

Deliberate exclusions, documented in ADRs: implicit grant and resource-owner password
grant (deprecated by the Security BCP — their absence is a feature), SAML (scope control;
OIDC federation only).

## 6. Security architecture (cross-cutting)

- Refresh tokens: opaque, 256-bit random, SHA-256 hashed at rest, rotated on every use,
  **family-based reuse detection** → replay of a rotated token revokes the whole family.
- Sessions: server-side only, 256-bit IDs hashed at rest, rotation on privilege change,
  sliding + absolute expiry, `HttpOnly`/`Secure`/`SameSite` cookies.
- Passwords: Argon2id (tuned parameters documented), constant-time everything,
  user-enumeration-safe flows (uniform responses + uniform timing on reset/login).
- Secrets: envelope encryption for keysmith private keys (AES-256-GCM DEK wrapped by
  KMS-or-local-master KEK); no plaintext key material at rest, redaction-safe logging.
- Audit: append-only events with hash chaining (each record embeds the previous record's
  hash) so tampering is detectable; Python tooling verifies chain integrity and renders
  compliance reports.
- Every project ships a `THREAT_MODEL.md` (STRIDE-lite: assets, trust boundaries, top
  abuse cases, mitigations) and ADRs for the decisions a reviewer would question.

## 7. Repository layout

Monorepo (`portfolio/`), Go workspace at the root, one module per Go project
(`github.com/aikazzh/portfolio/<project>` module paths):

```
portfolio/
├── README.md              # portfolio index — the first thing a reviewer sees
├── go.work
├── docs/design/           # this document + platform-level ADRs
├── keysmith/  idp/  sessiond/  sentinel/  bridge/   # Go services
├── portal/                # TypeScript (Fastify API + React UI + pg job worker)
├── console/               # Go API + React SPA
├── platform/              # terraform/, compose/, docs/{adr,observability.md}
└── site/                  # Astro portfolio site with /guide
```

Each project directory is self-contained: `README.md`, `docs/adr/`, `THREAT_MODEL.md`,
`Makefile`, `Dockerfile`, tests. Branching: feature branches merged to `main`, no direct
commits to `main`.

## 8. Build order & iteration protocol

Build order: `keysmith → idp → sessiond → sentinel → bridge → portal → console →
platform → site`. Dependencies flow backward only (idp consumes keysmith, never the reverse).

Before the portfolio is "done", three structured passes over every project, with findings
fixed and recorded in `docs/iteration-log.md`:

1. **Security pass** — attack each implementation: token substitution, redirect
   manipulation, timing oracles, race conditions on rotation/reuse paths, injection.
2. **Architecture pass** — failure modes (Redis down, IdP down, clock skew), horizontal
   scaling assumptions, graceful degradation, load behavior of hot paths.
3. **DX pass** — cold-start onboarding (`make dev` from clean checkout), API docs
   accuracy, error message quality, README truthfulness.

## 9. Deployment reality

No AWS credentials exist yet. Everything is built **deploy-ready**: Terraform validated
and planned (`terraform validate` + `plan` against mocked providers where possible),
images built locally, CI pipelines defined. The final handoff report states the exact
sequence (account → OIDC role for CI → `terraform apply`) and expected monthly cost.
Live demos activate when credentials arrive; until then, docker-compose is the demo.
