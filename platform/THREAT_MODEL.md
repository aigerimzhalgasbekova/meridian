# Threat model — platform (infrastructure)

Scope: the deployment layer only — network zones, secrets handling, supply
chain, CI/CD. Application-level threats live in each service's own
`THREAT_MODEL.md`.

## Assets

1. **Signing keys** (keysmith's encrypted keystore on EFS) — compromise forges
   every token in the platform.
2. **Service secrets** (SSM SecureStrings: bearer tokens, DSNs, OAuth client
   secrets).
3. **User data** (RDS: idp users/consents, portal accounts; Redis: sessions).
4. **The audit chain** (sentinel's EFS file) — integrity, not confidentiality.
5. **Deploy capability** (the CI role: whoever holds it ships code to all
   seven services).
6. **ALB access logs** (`meridian-dev-alb-logs-<acct>`) — records the full
   request URL, so it captures any credential a service puts in a query string
   (portal's single-use reset/verify tokens), correlated with client IPs and
   account identifiers. Treat read access to it as credential-adjacent, not as
   ordinary telemetry. Retention is 14 days to bound the window; the root fix
   is portal-side (deliver those tokens via POST or a URL fragment).

## Trust boundaries

| Boundary | Control |
|----------|---------|
| internet → ALB | Only 80/443 on the ALB SG; TLS 1.2+/1.3 policy; HTTP redirects to HTTPS |
| ALB → public services (idp, bridge, portal, console) | SG rule from ALB SG only. **prod**: private subnets, no public IPs. **dev**: public subnets with public IPs (no NAT) — the security group is the *only* control, so every ingress rule must be ALB-SG-sourced, never CIDR |
| service → internal service | Explicit SG pair per real consumer (idp→keysmith:8081); sessiond/sentinel accept nothing until a consumer exists |
| service → data stores | SG pairs (idp/portal→RDS, sessiond→Redis, keysmith/sentinel→EFS); nothing is publicly accessible; all encrypted at rest, Redis also in transit |
| GitHub → AWS | OIDC federation, trust policy pinned to `repo:${var.github_repository}:ref:refs/tags/*` (built in `envs/dev/ci.tf`, so verify against that file, not against a value copied here); no stored keys |
| operator → state | S3 remote state encrypted + versioned, DynamoDB locking; state contains no secret values (see below) |

## Top abuse cases & mitigations

**1. Secret exfiltration via Terraform state or CI logs.**
Secret values are created out-of-band (`aws ssm put-parameter`) and referenced
by ARN only; the RDS master password is AWS-managed in Secrets Manager. State
compromise yields topology, not credentials. Residual: SSM values are
decryptable by anyone with `ssm:GetParameter` + KMS on that path — the
per-service execution roles are scoped to exact ARNs to keep the blast radius
to one service.

**2. Lateral movement from a compromised public service.**
Distroless images (no shell, no package manager), read-only root filesystem
(except portal's outbox). **prod**: tasks run in private subnets, egress
through one NAT. **dev**: no NAT is created (`enable_nat = !local.cheap`), so
tasks run in public subnets with public IPs — the security group is the whole
boundary there, and it admits only the ALB SG and named peer SGs. A popped idp
task can reach keysmith:8081 (it must) but not Redis, not the EFS mounts, not
sessiond. Residual: egress is unrestricted (`0.0.0.0/0`) — acceptable for dev;
prod should add VPC endpoints + egress allowlisting.

**3. Malicious image reaches production (supply chain).**
CI gates: gosec + govulncheck (Go), npm audit (advisory), trivy config scan,
gitleaks on full history. ECR scans on push. The Terraform provider is part of
this surface too — it runs with the credentials that create every IAM role in
the stack — so `envs/dev/.terraform.lock.hcl` is committed (checksummed
baseline) and the constraint is `~> 5.100`, not a floating major. Deploys only happen from tag
pushes on this repo via the OIDC trust condition — a fork PR cannot assume the
deploy role, and `pull_request` workflows have no `id-token` permission.
Residual: no image signing/attestation (cosign) and third-party actions are
version-pinned but not SHA-pinned — both are the first hardening steps for a
real production tenant.

**4. Tampering with the audit chain.**
The chain is hash-linked (tamper-*evident* by construction) and sentinel is
its single writer on a dedicated EFS access point (uid 65532, `700`). No other
SG may reach the EFS mount targets. Residual: an attacker with sentinel's own
task credentials could truncate the file — periodic anchor export (S3 +
object lock) is the documented follow-up.

**5. CI role abuse via workflow injection.**
Workflows never interpolate event-controlled strings into `run:` (the tag name
goes through `env`). The deploy role cannot touch IAM (beyond `iam:PassRole`
on the two meridian task roles), state, or SSM — pushing a malicious image is
the worst case, which is already covered by branch protection on `main` and
tag-push restrictions.

**6. Keysmith keystore theft.**
The keystore file is itself envelope-encrypted (AES-256-GCM DEK under the
master KEK from SSM); EFS is additionally encrypted at rest and reachable only
from keysmith's SG. Stealing the file without the SSM master key yields
ciphertext. Residual: KEK lives in SSM, not KMS — migrating keysmith's KEK to
KMS (`keystore.NewLocalKEK` → a KMS-backed implementation) removes the
"one parameter unlocks everything" property and is the highest-value hardening
item on this list.

## Deliberate non-goals (dev environment)

WAF on the ALB, GuardDuty, multi-AZ NAT/RDS/Redis, image signing. Each is
listed in the cost/hardening trade-offs of the README; none change the
architecture. (VPC flow logs are *not* on this list — `modules/network`
creates them unconditionally, in both profiles.)

The dev IdP also seeds a demo realm with published credentials
(`alice`/`password123`, `web-app`/`web-app-secret`, see
`scripts/live-smoke.sh`) so the public instance has something to show. It is a
demonstration surface, not an accident: `IDP_SEED_DEMO` is off in the prod
profile, and no real realm may be deployed alongside the demo one.
