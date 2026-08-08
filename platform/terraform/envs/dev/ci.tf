# GitHub Actions → AWS federation (runbook step 6, as code).
#
# release.yml assumes this role via OIDC — no long-lived keys anywhere. The
# trust policy pins the exact repository; the permissions are the minimum the
# release workflow performs: push images to the meridian/* ECR repos and roll
# the ECS services.

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # GitHub's OIDC root CAs; AWS validates against its own trust store for this
  # provider, the thumbprint is retained for older API compatibility.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "ci_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      # Tags only — release.yml is the sole consumer and triggers on tag push,
      # so nothing needs a branch subject. Keeping refs/heads/main here would
      # silently hand deploy rights to any future main-triggered workflow that
      # adds `id-token: write`.
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/tags/*"]
    }
  }
}

data "aws_iam_policy_document" "ci_permissions" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [for r in aws_ecr_repository.svc : r.arn]
  }
  statement {
    sid = "EcsDeploy"
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:RegisterTaskDefinition",
    ]
    resources = ["*"] # Describe/Register don't support resource ARNs; UpdateService is condition-scoped below
    condition {
      test     = "ArnEqualsIfExists"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.this.arn]
    }
  }
  statement {
    # Task-definition re-registration passes the existing roles through — the
    # exact roles modules/service creates for the services in local.services,
    # named individually rather than wildcarded. `${local.name}-*-task` would
    # still auto-enrol any future task role (a migration runner, a backup job)
    # into what CI may pass, with no policy change and no review signal.
    sid     = "PassTaskRoles"
    actions = ["iam:PassRole"]
    resources = flatten([
      for s in local.services : [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-${s}-task",
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-${s}-execution",
      ]
    ])
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = "meridian-ci"
  assume_role_policy = data.aws_iam_policy_document.ci_trust.json
}

resource "aws_iam_role_policy" "ci" {
  name   = "meridian-ci"
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.ci_permissions.json
}

output "ci_role_arn" {
  description = "Set as the AWS_ROLE_ARN repository secret in GitHub (it embeds the account id)."
  value       = aws_iam_role.ci.arn
}
