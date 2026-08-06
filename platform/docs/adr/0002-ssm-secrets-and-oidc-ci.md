# ADR 0002 — SSM Parameter Store for secrets, OIDC federation for CI

**Status:** accepted · 2026-07-10

## Secrets: SSM Parameter Store SecureStrings

Task definitions reference parameters by ARN (`secrets` → `valueFrom`); ECS
injects values at container start. Parameters are created out-of-band by the
runbook, so secret **values never touch Terraform state, tfvars, or CI logs**
— Terraform only ever handles ARNs built by convention
(`/meridian/dev/<service>/<VAR>`).

Why not Secrets Manager everywhere: it costs $0.40/secret/mo and its killer
feature (managed rotation Lambdas) applies to none of these secrets — they are
service-to-service bearer tokens rotated by humans. The one place rotation is
managed — the RDS master password — does use Secrets Manager, via
`manage_master_user_password` (AWS owns it end to end).

Least privilege: each service's ECS execution role gets `ssm:GetParameters` on
exactly the ARNs its task definition declares — not `/meridian/*`. Compromise
of one service leaks that service's secrets only.

## CI: GitHub OIDC, no long-lived keys

`release.yml` authenticates with `aws-actions/configure-aws-credentials` via
OIDC (`permissions: id-token: write`). There are no `AWS_ACCESS_KEY_ID`
repository secrets to leak, rotate, or gitleaks-scan for.

One-time setup:

1. IAM → Identity providers → add `token.actions.githubusercontent.com`
   (audience `sts.amazonaws.com`).
2. Role `meridian-ci`, trust policy:

   ```json
   {
     "Effect": "Allow",
     "Principal": { "Federated": "arn:aws:iam::<acct>:oidc-provider/token.actions.githubusercontent.com" },
     "Action": "sts:AssumeRoleWithWebIdentity",
     "Condition": {
       "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
       "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:<owner>/portfolio:ref:refs/tags/*" }
     }
   }
   ```

   Permissions: ECR push to `meridian/*` repos; `ecs:DescribeTaskDefinition`,
   `ecs:RegisterTaskDefinition`, `ecs:UpdateService`, `ecs:DescribeServices`
   on the `meridian-dev` cluster; `iam:PassRole` restricted to the
   `meridian-dev-*-task` / `-execution` roles.
3. Repo **secrets** `AWS_ROLE_ARN` and `ECR_REGISTRY`; repo **variable**
   `AWS_REGION`. The first two embed the AWS account id, and repository
   variables are interpolated into workflow logs verbatim while secrets are
   masked — on a public repo that is the difference between publishing the
   account id and not. `AWS_REGION` carries nothing sensitive.

The trust policy's `sub` condition pins deploys to **tag pushes on this
repository** — a compromised PR branch or fork cannot assume the role.
release.yml is also tag-triggered only, so no fork-originated run is ever in a
position to ask for the secrets. Until the config exists, release.yml exits
with a notice instead of failing (a supported state).
