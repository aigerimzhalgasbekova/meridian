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
      # Tags and main only — a PR from a fork can never assume this role.
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:ref:refs/tags/*",
        "repo:${var.github_repository}:ref:refs/heads/main",
      ]
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
    # Task-definition re-registration passes the existing roles through.
    sid       = "PassTaskRoles"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-*"]
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
  description = "Set as the AWS_ROLE_ARN repository variable in GitHub."
  value       = aws_iam_role.ci.arn
}
