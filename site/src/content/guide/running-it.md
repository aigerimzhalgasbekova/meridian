---
title: Running it
chapter: 9
summary: The deployment design — ECS Fargate, RDS, ElastiCache, CloudWatch — CI security gates, and exactly what's pending AWS credentials.
---

Seven services exist and pass their suites. This chapter covers how they're designed to run in production, what runs today, and — honestly — what's blocked on an AWS account that doesn't exist yet.

## What runs today

Every service runs standalone on a laptop with its dependencies faked or embedded, because that was a design rule, not an afterthought:

```sh
make run-dev            # keysmith, sessiond, sentinel, bridge, console
npm run dev             # portal (API + web)
IDP_DEV_MODE=1 ...      # idp, against a dev-mode keysmith
```

- keysmith: ephemeral in-memory keys (`KEYSMITH_DEV_MODE=1`).
- idp: in-memory store, seeded demo realm, real keysmith over HTTP.
- sessiond: embedded miniredis, browser demo at `/demo`.
- bridge: built-in fake OIDC upstreams — the full federation flow, email-collision handling, and account linking, with no cloud accounts.
- console: seeded demo world with six personas and pre-minted dev tokens.

The same seams that enable this are the production integration points: every fake sits behind the interface its real counterpart implements.

## The AWS design

From the [platform design doc](https://github.com/aikazzh/portfolio/blob/main/docs/design/2026-07-09-meridian-platform-design.md), the target architecture is deliberately boring and AWS-native — no self-hosted observability stack, no Kubernetes:

| Concern | Choice |
|---|---|
| Compute | ECS Fargate, one service per Meridian service |
| System of record | RDS Postgres (users, clients, token hashes, audit) |
| Session / rate-limit state | ElastiCache Redis |
| Ingress + TLS | ALB + ACM |
| Email (portal) | SES |
| This site | S3 + CloudFront |
| Observability | CloudWatch + X-Ray via ADOT |
| Secrets | KMS-backed — keysmith's KEK interface is exactly `Wrap`/`Unwrap` |
| IaC | Terraform ≥ 1.10, per-environment stacks, remote state |

Several design decisions made months of AWS work into drop-ins:

- **keysmith's KEK seam is KMS-shaped by construction** ([ADR 0002](https://github.com/aikazzh/portfolio/blob/main/keysmith/docs/adr/0002-envelope-encryption.md)): cloud KMS APIs *are* Wrap/Unwrap. Swapping the local master key for KMS never touches key-material code.
- **sentinel's anchor records** are the mount point for external notarization (S3 object-lock / KMS-signed anchors) that makes the audit chain tamper-evident even against whole-file rewrite.
- **The stores are already dual-implementation.** idp's Postgres store exists and is integration-tested; portal's schema ships in the repo; sessiond needs only a Redis URL.
- **Every service is environment-configured** with documented variables — the twelve-factor part was free.

## CI security gates

The design doc specifies CI with security gates rather than a plain build-test pipeline: `go test -race` and the TypeScript suites as table stakes, plus `govulncheck` / `npm audit` dependency scanning, static analysis, and the cross-language audit-chain verification as a pipeline step (the Python verifier against a Go-written chain — the same check the test suites run). CI lives in `.github/workflows/`: `ci.yml` runs the suites and the security gates on every PR, `release.yml` builds and pushes the images on a tag.

The iteration protocol from the design doc also belongs to this chapter: before the portfolio is called done, three structured passes over every project — a security pass (attack the implementations: token substitution, redirect manipulation, timing oracles, races on rotation/reuse paths), an architecture pass (failure modes: Redis down, IdP down, clock skew), and a DX pass (cold-start onboarding from a clean checkout, README truthfulness).

## What's honestly pending

An AWS account now exists, but nothing is applied to it yet, so the following are designed and plan-verified but not deployed:

- The `platform/` Terraform stacks (the eighth project) — now `terraform plan`-clean against the real account (166 resources, no diagnostics), but nothing has been applied.
- Live demo URLs on this site — each project card says "deploy pending" and links to the code instead. The URLs live in [one config file](https://github.com/aikazzh/portfolio/blob/main/site/src/config.ts); when the platform deploys, they're a one-line change each.
- SES-backed mail in portal (the `MailTransport` interface is one method; dev writes JSON files to an outbox).
- KMS-backed KEK in keysmith, sentinel's external anchor push, and CloudWatch/X-Ray wiring.

The remaining handoff sequence, per the design doc: bootstrap remote state, get a domain plus a DNS-validated ACM certificate, set up an OIDC role for CI (no long-lived keys), `terraform apply` per environment, then swap the demo URLs into this site's config. Until then, the local dev modes are the demo — which is arguably the more reviewable artifact anyway: `make run-dev` asks nothing of the reviewer but a Go toolchain.

## Why "deploy-ready" is a real claim

It would be easy to hand-wave "cloud-ready" — the term usually means "we hope". Here it's checkable in the code: the interfaces that fake infrastructure in tests are the same interfaces production implements ([portal's queue](https://github.com/aikazzh/portfolio/blob/main/portal/docs/adr/0001-postgres-job-queue.md) runs the identical test suite against memory and real Postgres; [sessiond's Lua scripts](https://github.com/aikazzh/portfolio/blob/main/sessiond/docs/adr/0002-lua-scripts-for-atomicity.md) execute unmodified under miniredis's gopher-lua and production Redis). The deployment risk that remains is the honest kind — IAM policies, VPC wiring, cost tuning — not "will the code work off my laptop".
