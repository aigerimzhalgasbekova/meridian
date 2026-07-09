# Meridian — Identity & Access Management Platform

A portfolio of eight interlocking projects forming a realistic, standards-aligned IAM
platform: OAuth 2.0 / OpenID Connect authorization server, key management, distributed
sessions, adaptive security, SSO federation, self-service identity, RBAC control plane,
and the infrastructure to run it all.

> **Status: under construction.** This README is finalized last; see
> [docs/design/2026-07-09-meridian-platform-design.md](docs/design/2026-07-09-meridian-platform-design.md)
> for the full platform design.

| Project | What it is | Language |
|---------|-----------|----------|
| [keysmith](keysmith/) | Key management & JWT signing — zero-downtime rotation, hardened minimal JOSE | Go |
| [idp](idp/) | Multi-tenant OAuth 2.0 / OIDC authorization server | Go |
| [sessiond](sessiond/) | Distributed session service — cross-node invalidation | Go + Redis |
| [sentinel](sentinel/) | Rate limiting, brute-force defense, risk scoring, tamper-evident audit | Go + Python |
| [bridge](bridge/) | SSO federation gateway (Google / Entra ID) | Go |
| [portal](portal/) | Self-service identity portal — password reset, MFA, async jobs | TypeScript |
| [console](console/) | RBAC control plane that explains every decision | Go + React |
| [platform](platform/) | Terraform (AWS), CI/CD, local stack, observability | HCL / YAML |
| [site](site/) | Portfolio site + `/guide` engineering walkthrough | Astro |
