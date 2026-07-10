# Meridian — handoff report

*2026-07-11. The portfolio is built, iterated, deployed, and verified live.*

## What exists

Eight projects in this monorepo, each a different architectural problem:

| Project | What it demonstrates | Verified by |
|---|---|---|
| keysmith | Key lifecycle, zero-downtime rotation, allowlist-only JOSE, envelope encryption | 94 Go tests, `-race` |
| idp | OAuth 2.0 / OIDC authorization server: PKCE, device flow, refresh-family reuse detection, multi-tenant realms | 99+ Go tests; shared store contract runs against memory *and* real Postgres |
| sessiond | Distributed sessions: Lua atomicity, pub/sub invalidation with bounded staleness | miniredis + real-Redis script tests |
| sentinel | Rate limiting, anti-DoS lockout, risk scoring, hash-chained audit | 59+ Go tests + 11 Python; chain verified cross-language both directions |
| bridge | RP-side OIDC federation: Entra tenanted issuers, never-match-by-email, circuit breakers | 56 Go tests incl. fake-upstream e2e |
| portal | Self-service identity: enumeration-safe reset, hand-rolled RFC 6238 TOTP, Postgres job queue, TOTP-at-rest envelope encryption | 50+ vitest incl. shared memory/Postgres contracts |
| console | RBAC engine whose every decision returns an explanation trace; dog-fooded API | 68 Go tests asserting on traces, not just verdicts |
| platform | Terraform (module-per-concern), OIDC CI, compose stack, observability | `terraform apply`'d for real; 12/12 compose smoke; **16/16 live smoke on AWS** |

Plus `site/` — the Astro portfolio site with the 10-chapter `/guide`, deployed to CloudFront.

## What is live right now

Account `565398310177`, region `eu-west-1`, ~166 Terraform-managed resources
(state in `s3://meridian-terraform-state-565398310177`):

- **ALB** `meridian-dev-914590008.eu-west-1.elb.amazonaws.com` with host routing and the `*.iammeridian.cc` ACM cert; XFF handling pinned (`append` + drop-invalid-headers) because idp's brute-force guard depends on it.
- **7 Fargate services**, all running: idp/sso/portal/console public behind the ALB; keysmith/sessiond/sentinel VPC-internal via Cloud Map.
- **RDS Postgres** (idp + portal databases; portal verifies TLS against the pinned Amazon CA bundle), **ElastiCache Redis** (TLS) for sessiond.
- **CloudFront** `d2pnpsrujas06i.cloudfront.net` serving the site from S3 behind OAC.
- **CloudWatch** dashboard + 5xx / p99 / unhealthy-host / CPU alarms; ALB access logs to S3.
- **GitHub OIDC CI role** `meridian-ci`, trust pinned to `aigerimzhalgasbekova/meridian` tags + main. Repo variables `AWS_ROLE_ARN`, `AWS_REGION`, `ECR_REGISTRY` are set — tagging `v0.1.0` runs release.yml end to end.
- Secrets in SSM SecureStrings under `/meridian/dev/…`; RDS master password AWS-managed in Secrets Manager. Nothing sensitive in state, tfvars, or CI.

**Verified live** (16-check smoke, ALB-pinned TLS): health on all four public
hosts, OIDC discovery, realm JWKS re-published from keysmith over the VPC,
login → authorization code → keysmith-signed access/ID/refresh tokens →
userinfo → refresh rotation → replay rejected with family revocation, portal
API on RDS, bridge and console pages.

## The one thing only you can do: DNS (Cloudflare)

I have no Cloudflare access. Add these records to `iammeridian.cc`
(DNS-only / grey cloud recommended, at least initially — Cloudflare proxying
would re-terminate TLS in front of the ALB and hide client IPs):

| Type | Name | Target |
|---|---|---|
| CNAME | `idp` | `meridian-dev-914590008.eu-west-1.elb.amazonaws.com` |
| CNAME | `sso` | `meridian-dev-914590008.eu-west-1.elb.amazonaws.com` |
| CNAME | `portal` | `meridian-dev-914590008.eu-west-1.elb.amazonaws.com` |
| CNAME | `console` | `meridian-dev-914590008.eu-west-1.elb.amazonaws.com` |
| CNAME | `@` (apex, CF flattens) | `d2pnpsrujas06i.cloudfront.net` |
| CNAME | `www` | `d2pnpsrujas06i.cloudfront.net` |

(The ACM validation CNAME you already added must stay — it covers renewals.)
After that: `https://iammeridian.cc` is the portfolio, `https://idp.iammeridian.cc/realms/demo/.well-known/openid-configuration` is the live IdP. Demo login: `alice` / `password123`.

## Honestly pending

- **Bridge upstreams are placeholders** — register a Google OAuth app (redirect URI `https://sso.iammeridian.cc/callback/google`) and overwrite `/meridian/dev/bridge/BRIDGE_GOOGLE_CLIENT_ID|SECRET` in SSM, then roll the service.
- **Portal mail** writes to a container-local outbox; the SES transport is a one-method seam.
- **idp→RDS TLS** is `sslmode=require` (encrypted, unverified) — portal got the verify-full treatment; giving idp's distroless image the same CA bundle is the next hardening step.
- **X-Ray tracing** designed but not wired; KMS-backed KEK for keysmith; sentinel external anchoring.
- **prod profile** exists in Terraform (multi-AZ, NAT, WAF, deletion protection) but only `dev` (cheap/ephemeral: single-AZ, 1-day backups — an AWS free-plan cap) is applied.
- Free-plan quirk to remember: RDS `backup_retention_period > 1` fails with `FreeTierRestrictionError`.

## Operational notes that will bite otherwise

- The service module sets `ignore_changes = [task_definition]` so CI releases don't fight Terraform. Consequence: after changing env/secrets via Terraform, roll the service yourself — `aws ecs update-service --cluster meridian-dev --service <name> --task-definition meridian-dev-<name> --force-new-deployment`.
- `terraform.tfvars` is gitignored and holds the cert ARNs; `versions.tf` carries the S3 backend (bucket name is account-suffixed — the bare name was globally taken).
- Cost: roughly $170/mo at dev sizing. `terraform destroy` in `platform/terraform/envs/dev` tears it all down (the ALB-logs S3 bucket may need emptying first).

## Where to read more

- `README.md` — quickstarts that were actually run, architecture, test counts.
- `platform/README.md` — the runbook this deployment followed (updated with everything learned doing it for real).
- Each project's `README.md`, `docs/adr/`, `THREAT_MODEL.md`.
- The live guide: `/guide` on the site — ten chapters, including the bugs found and what would be done differently.
