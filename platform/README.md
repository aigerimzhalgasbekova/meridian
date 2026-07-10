# platform — infrastructure as a product

Deployment layer for the seven Meridian services: Terraform for AWS (ECS
Fargate), CI/CD with security gates, and a one-command local stack.

```
platform/
├── terraform/          # AWS: modules/{network,service,data,observability} + envs/dev
├── compose/            # local stack: docker-compose.yml + smoke.sh
├── docs/
│   ├── adr/            # 0001 Fargate-over-EKS, 0002 SSM secrets + OIDC CI
│   └── observability.md
└── THREAT_MODEL.md
```

CI lives in `.github/workflows/` at the repo root (`ci.yml`, `release.yml`).

## Architecture (envs/dev)

```
                        internet
                           │
                     ┌─────▼─────┐   ACM TLS, host-based routing
                     │    ALB    │   idp.* sso.* portal.* console.*
                     └─────┬─────┘
        ┌────────────┬─────┴─────┬────────────┐          public subnets
  ──────┼────────────┼───────────┼────────────┼──────────────────────────
        ▼            ▼           ▼            ▼           private subnets
   ┌─────────┐  ┌─────────┐ ┌─────────┐ ┌─────────┐   (egress via 1 NAT)
   │  idp    │  │ bridge  │ │ portal  │ │ console │      ECS Fargate
   │  :8080  │  │  :8080  │ │  :3000  │ │  :8085  │
   └──┬───┬──┘  └─────────┘ └────┬────┘ └─────────┘
      │   │ http://keysmith.meridian.local:8081 (Cloud Map DNS)
      │   └────────►┌──────────┐    ┌──────────┐    ┌──────────┐
      │             │ keysmith │    │ sessiond │    │ sentinel │  internal
      │             │  :8081   │    │  :8082   │    │  :8084   │  services
      │             └────┬─────┘    └────┬─────┘    └────┬─────┘
      ▼                  ▼               ▼               ▼
   ┌──────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
   │ RDS PG   │     │  EFS    │     │ Redis   │     │  EFS    │
   │ idp,     │◄─┐  │ keystore│     │ sessions│     │ audit   │
   │ portal   │  │  └─────────┘     └─────────┘     │ chain   │
   └──────────┘  └── portal                         └─────────┘
```

- **One security-group rule per real consumer** (idp→keysmith:8081,
  idp/portal→postgres:5432, sessiond→redis:6379, keysmith/sentinel→EFS:2049).
  sessiond and sentinel have no in-code consumers yet, so nothing may reach
  them — the rule gets added with the wiring, not before.
- **Secrets**: SSM Parameter Store SecureStrings under `/meridian/dev/...`,
  referenced by ARN in task definitions; never in Terraform state, tfvars, or
  CI. The RDS master password is AWS-managed in Secrets Manager.
- **Single-writer services pinned to one task**: keysmith (file keystore) and
  sentinel (hash-chained audit file) run on EFS with `max_count = 1`.

## Cost estimate (eu-central-1, dev, monthly)

| Item | Sizing | ~USD |
|------|--------|-----:|
| Fargate | 7 × (0.25 vCPU / 0.5 GB), 730 h | 72 |
| ALB | 1 + light LCU | 23 |
| NAT gateway | single AZ | 35 |
| RDS Postgres | db.t4g.micro, 20 GB gp3, single-AZ | 16 |
| ElastiCache Redis | cache.t4g.micro, 1 node | 13 |
| EFS | < 1 GB | 1 |
| CloudWatch | dashboard + ~25 alarms + logs | 8 |
| ECR / Cloud Map / Secrets Manager | | 2 |
| **Total** | | **~170** |

Biggest levers if that's too much: stop the cluster overnight (Fargate is
per-second), or drop the four internal/demo services from `desired_count`.

## Runbook: when AWS credentials exist

1. **Bootstrap remote state** — run the S3/DynamoDB commands commented in
   `terraform/envs/dev/versions.tf`, then uncomment the `backend "s3"` block.
2. **DNS + TLS** — request an ACM certificate for `*.dev.<your-domain>` in the
   target region; put its ARN and the domain in `terraform.tfvars` (copy from
   `terraform.tfvars.example`).
3. **Pre-apply secrets** — create the SSM SecureStrings that don't depend on
   infrastructure (values via `openssl rand -hex 32`; master key
   `openssl rand -base64 32`):

   ```sh
   P=/meridian/dev
   aws ssm put-parameter --type SecureString --name $P/keysmith/KEYSMITH_MASTER_KEY    --value "$(openssl rand -base64 32)"
   aws ssm put-parameter --type SecureString --name $P/keysmith/KEYSMITH_SIGNER_TOKENS --value "$SIGNER"
   aws ssm put-parameter --type SecureString --name $P/keysmith/KEYSMITH_ADMIN_TOKENS  --value "$(openssl rand -hex 32)"
   aws ssm put-parameter --type SecureString --name $P/idp/IDP_KEYSMITH_TOKEN          --value "$SIGNER"   # same value
   aws ssm put-parameter --type SecureString --name $P/idp/IDP_REGISTRATION_TOKEN      --value "$(openssl rand -hex 32)"
   aws ssm put-parameter --type SecureString --name $P/sessiond/SESSIOND_API_TOKENS    --value "$(openssl rand -hex 32)"
   aws ssm put-parameter --type SecureString --name $P/sentinel/SENTINEL_TOKEN         --value "$(openssl rand -hex 32)"
   aws ssm put-parameter --type SecureString --name $P/bridge/BRIDGE_HMAC_KEY          --value "$(openssl rand -hex 32)"
   aws ssm put-parameter --type SecureString --name $P/bridge/BRIDGE_GOOGLE_CLIENT_ID     --value "<from Google console>"
   aws ssm put-parameter --type SecureString --name $P/bridge/BRIDGE_GOOGLE_CLIENT_SECRET --value "<from Google console>"
   aws ssm put-parameter --type SecureString --name $P/console/CONSOLE_HS256_KEY       --value "$(openssl rand -hex 32)"
   ```

4. **Apply** — `cd terraform/envs/dev && terraform init && terraform plan &&
   terraform apply`. Tasks will crash-loop until steps 5–7 complete; ECS keeps
   retrying, that's fine.
5. **Database bootstrap** — read the master password from the Secrets Manager
   ARN in `terraform output postgres_master_secret_arn`, then (via a bastion
   task or `aws ecs execute-command` helper container):
   `CREATE DATABASE portal;` and apply `portal/server/schema.sql` to it
   (idp migrates its own database on boot). Write the DSNs:

   ```sh
   # sslmode=require: the parameter group sets rds.force_ssl=1 server-side
   # anyway; require just makes the client-side expectation explicit. Upgrade
   # to verify-full + sslrootcert=<RDS CA bundle> if you want to authenticate
   # the server cert too.
   aws ssm put-parameter --type SecureString --name $P/idp/IDP_DATABASE_URL \
     --value "postgres://meridian:<pw>@<postgres_endpoint>:5432/idp?sslmode=require"
   aws ssm put-parameter --type SecureString --name $P/portal/DATABASE_URL \
     --value "postgres://meridian:<pw>@<postgres_endpoint>:5432/portal?sslmode=require"
   ```

6. **CI federation** — create the GitHub OIDC provider + `meridian-ci` role
   (see `docs/adr/0002-ssm-secrets-and-oidc-ci.md`), set repo variables
   `AWS_ROLE_ARN`, `AWS_REGION`, `ECR_REGISTRY`.
7. **First release** — `git tag v0.1.0 && git push --tags`. release.yml builds
   and pushes all seven images (`:v0.1.0` + `:dev`) and rolls the services.
8. **DNS records** — CNAME `idp/sso/portal/console.dev.<domain>` to
   `terraform output alb_dns_name`.
9. **Verify** — `curl https://idp.dev.<domain>/healthz`, then the smoke flow
   from `compose/smoke.sh` with `IDP_URL=https://idp.dev.<domain>` (the dev
   realm only exists with `IDP_DEV_MODE=1`; in AWS, create a realm via the
   registration API first).

## Local stack

See [compose/README.md](compose/README.md) — `docker compose up -d --build`
then `./smoke.sh` runs JWKS → discovery → a full authorization-code flow.
