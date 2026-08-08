# Meridian dev environment — composition root.
#
# Wiring source of truth: each service's cmd/*/main.go (env vars) and
# Dockerfile (port). Public services (idp, bridge, portal, console) sit behind
# one shared ALB with host-based routing; internal services (keysmith,
# sessiond, sentinel) are reachable only inside the VPC via Cloud Map DNS
# (<name>.meridian.local) and explicit security-group pairs.
#
# Secrets are never inline: task definitions reference SSM SecureString
# parameters under /meridian/dev/<service>/<VAR>. The bootstrap runbook
# (../../README.md) creates them before the first apply.

data "aws_caller_identity" "current" {}

locals {
  name     = "meridian-${var.environment}"
  services = ["keysmith", "idp", "sessiond", "sentinel", "bridge", "portal", "console"]

  # prod = hardened + durable; anything else = cheap + ephemeral (see variables.tf).
  is_prod   = var.environment == "prod"
  ephemeral = !local.is_prod # RDS: no deletion protection, no final snapshot
  cheap     = !local.is_prod # no NAT/WAF/Container Insights

  # SSM SecureString parameters created out-of-band (runbook step 3).
  ssm = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/meridian/${var.environment}"

  sd_domain = "meridian.local"
}

# --- Shared plumbing ---------------------------------------------------------

module "network" {
  source     = "../../modules/network"
  name       = local.name
  enable_nat = !local.cheap
}

module "data" {
  source             = "../../modules/data"
  name               = local.name
  vpc_id             = module.network.vpc_id
  private_subnet_ids = module.network.private_subnet_ids
  ephemeral          = local.ephemeral
}

resource "aws_ecr_repository" "svc" {
  for_each = toset(local.services)

  name                 = "meridian/${each.key}"
  image_tag_mutability = "MUTABLE" # the :dev tag is re-pointed by release.yml

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name = "containerInsights"
    # The CPU alarms/dashboard use the base AWS/ECS namespace, which exists
    # without Container Insights, so cheap mode drops it with no alarm loss.
    value = local.cheap ? "disabled" : "enabled"
  }
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name = local.sd_domain
  vpc  = module.network.vpc_id
}

# --- ALB access logs (SEC04-BP01 sibling: capture request-level activity) ---

data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "${local.name}-alb-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      # Access-log records carry the full request line. Portal's one-time
      # tokens never appear there: they are mailed in the URL fragment, which
      # browsers do not transmit (portal/server/src/app.ts), and the reader
      # accepts nothing else (portal/web/src/token.ts). What is left is
      # bridge's ?code=, already spent by the time the request completes.
      # Two weeks is enough for forensics on a dev stack and bounds the window.
      days = 14
    }
  }
}

data "aws_iam_policy_document" "alb_logs" {
  # Regional ELB log-delivery account writes objects under the ALB's prefix.
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/${local.name}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs.json
}

resource "aws_lb" "this" {
  name               = local.name
  load_balancer_type = "application"
  security_groups    = [module.network.alb_security_group_id]
  subnets            = module.network.public_subnet_ids

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = local.name
    enabled = true
  }
  depends_on = [aws_s3_bucket_policy.alb_logs]

  # Services key their brute-force guards on the LAST X-Forwarded-For hop.
  # That is only sound because the ALB appends the IP it actually observed;
  # a client-supplied XFF can prepend entries but never forge the final one.
  # Stated explicitly rather than inherited from an AWS default, because the
  # security of the guard depends on it. Tasks accept ingress only from the
  # ALB security group (modules/service), so the ALB cannot be bypassed.
  xff_header_processing_mode = "append"

  # Reject requests carrying malformed headers instead of normalizing them.
  drop_invalid_header_fields = true
}

# --- WAFv2 (SEC04-BP01: filter common web attacks + rate-limit) -------------

resource "aws_wafv2_web_acl" "this" {
  count = local.cheap ? 0 : 1

  name  = "${local.name}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000 # requests per 5-minute window, per source IP
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count = local.cheap ? 0 : 1

  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "unknown host"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# --- Services ----------------------------------------------------------------

locals {
  common = {
    env_name    = local.name
    cluster_arn = aws_ecs_cluster.this.arn
    vpc_id      = module.network.vpc_id
    # No NAT in cheap mode: tasks run in public subnets with public IPs for
    # egress. Their SGs still allow ingress only from the ALB / peer services.
    subnet_ids                     = local.cheap ? module.network.public_subnet_ids : module.network.private_subnet_ids
    assign_public_ip               = local.cheap
    service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.this.id
    region                         = var.region
  }
}

# keysmith — internal. Every signature in the platform originates here.
# File-backed keystore on EFS (losing it would invalidate all issued tokens).
module "keysmith" {
  source = "../../modules/service"

  name           = "keysmith"
  image          = "${aws_ecr_repository.svc["keysmith"].repository_url}:${var.image_tag}"
  container_port = 8081

  env = {
    KEYSMITH_ADDR       = ":8081"
    KEYSMITH_STORE_PATH = "/data/keys.json"
  }
  # ONE-WAY DEPLOY: the first v2 keysmith to start rewrites /data/keys.json at
  # document version 2, and a pre-v2 image refuses to open it ("understands
  # 1..1"). Downgrading keysmith after that means restoring the keystore from an
  # EFS recovery point, not `ecs update-service --task-definition <previous>`.
  # Take one before the upgrade deploy; this service is the platform's only
  # signer, so a keystore you cannot open is a total token and JWKS outage.
  secrets = {
    KEYSMITH_MASTER_KEY    = "${local.ssm}/keysmith/KEYSMITH_MASTER_KEY"
    KEYSMITH_SIGNER_TOKENS = "${local.ssm}/keysmith/KEYSMITH_SIGNER_TOKENS"
    KEYSMITH_ADMIN_TOKENS  = "${local.ssm}/keysmith/KEYSMITH_ADMIN_TOKENS"
  }

  efs = {
    file_system_id  = module.data.efs_file_system_id
    access_point_id = module.data.efs_access_point_keysmith
    container_path  = "/data"
  }

  # keysmithd flocks <store>.lock for the process lifetime, so the replacement
  # task cannot boot while the old one is running: the default 100/200 rolling
  # deploy would crash-loop every release. (The flock is only cross-host if the
  # mount forwards locks — Fargate-managed EFS mounts do; no mount option here
  # sets local_lock, and efs_volume_configuration above exposes none.)
  stop_before_start = true

  # The keystore file assumes a single writer.
  # ponytail: pin to one task; multi-writer needs a shared-store keysmith backend.
  desired_count = 1
  min_count     = 1
  max_count     = 1

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# idp — public OAuth2/OIDC authorization server.
module "idp" {
  source = "../../modules/service"

  name           = "idp"
  image          = "${aws_ecr_repository.svc["idp"].repository_url}:${var.image_tag}"
  container_port = 8080

  env = {
    IDP_ADDR         = ":8080"
    IDP_BASE_URL     = "https://idp.${var.domain}"
    IDP_KEYSMITH_URL = "http://keysmith.${local.sd_domain}:8081"
    # Safe here and only here: tasks accept ingress solely from the ALB
    # security group, and the ALB is pinned to xff_header_processing_mode
    # = "append", so the last X-Forwarded-For hop cannot be forged.
    IDP_TRUST_PROXY = "1"
    # Demo deployment: provision the demo realm/users/clients idempotently on
    # boot so the public instance has something to show. The credentials are
    # published (scripts/live-smoke.sh), so this is a demonstration surface —
    # it routes through the profile flag like every other dev/prod difference
    # rather than being a standalone knob someone must remember to flip.
    IDP_SEED_DEMO = local.is_prod ? "0" : "1"
  }
  secrets = {
    # IDP_KEYSMITH_TOKEN must be one of keysmith's KEYSMITH_SIGNER_TOKENS.
    IDP_KEYSMITH_TOKEN     = "${local.ssm}/idp/IDP_KEYSMITH_TOKEN"
    IDP_DATABASE_URL       = "${local.ssm}/idp/IDP_DATABASE_URL"
    IDP_REGISTRATION_TOKEN = "${local.ssm}/idp/IDP_REGISTRATION_TOKEN"
  }

  alb = {
    listener_arn      = aws_lb_listener.https.arn
    security_group_id = module.network.alb_security_group_id
    host              = "idp.${var.domain}"
    priority          = 10
    health_check_path = "/healthz"
  }

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# sessiond — internal distributed session store over Redis.
module "sessiond" {
  source = "../../modules/service"

  name           = "sessiond"
  image          = "${aws_ecr_repository.svc["sessiond"].repository_url}:${var.image_tag}"
  container_port = 8082

  env = {
    SESSIOND_ADDR = ":8082"
    # rediss:// — ElastiCache transit encryption is on.
    SESSIOND_REDIS_URL = "rediss://${module.data.redis_endpoint}:6379"
  }
  secrets = {
    SESSIOND_API_TOKENS = "${local.ssm}/sessiond/SESSIOND_API_TOKENS"
  }

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# sentinel — internal decision service; hash-chained audit log on EFS.
module "sentinel" {
  # The audit store flocks its JSONL file: exactly one writer, so deployments
  # must stop the old task before starting the new one.
  stop_before_start = true

  source = "../../modules/service"

  name           = "sentinel"
  image          = "${aws_ecr_repository.svc["sentinel"].repository_url}:${var.image_tag}"
  container_port = 8084

  env = {
    SENTINEL_ADDR       = ":8084"
    SENTINEL_AUDIT_PATH = "/data/audit.jsonl"
  }
  secrets = {
    SENTINEL_TOKEN = "${local.ssm}/sentinel/SENTINEL_TOKEN"
  }

  efs = {
    file_system_id  = module.data.efs_file_system_id
    access_point_id = module.data.efs_access_point_sentinel
    container_path  = "/data"
  }

  # Audit chain file assumes a single writer (hash chain ordering).
  desired_count = 1
  min_count     = 1
  max_count     = 1

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# bridge — public SSO federation gateway (Google / Entra ID upstream).
# /healthz is pure liveness; /healthz/providers (503 while an upstream
# breaker is open) is readiness and deliberately NOT the ALB check — an
# IdP outage must not recycle healthy bridge tasks.
module "bridge" {
  source = "../../modules/service"

  name           = "bridge"
  image          = "${aws_ecr_repository.svc["bridge"].repository_url}:${var.image_tag}"
  container_port = 8080

  env = {
    BRIDGE_ADDR     = ":8080"
    BRIDGE_BASE_URL = "https://sso.${var.domain}"
    # BRIDGE_APPS ("id=https://host/callback,…") is deliberately UNSET here.
    # Registering an app makes /login/{provider}?app=id reachable, and
    # deliverAssertion redirects the browser to that callback with the signed
    # assertion — subject, email, email_verified, name — in the QUERY STRING.
    # A placeholder host is therefore not inert: it ships a real user's
    # identity to whoever operates it, in their access log and every
    # intermediary's. example.com is IANA-operated and resolves, so it is the
    # worst possible choice. Unset, every ?app= is a 400 and nothing leaks.
    # Add this in the same change that brings up the first real relying app,
    # pointed at a host this account owns. bridged validates it at STARTUP, so
    # a typo is a crash-loop, not a request-time 400 — review the plan first.
  }
  secrets = {
    BRIDGE_HMAC_KEY             = "${local.ssm}/bridge/BRIDGE_HMAC_KEY"
    BRIDGE_GOOGLE_CLIENT_ID     = "${local.ssm}/bridge/BRIDGE_GOOGLE_CLIENT_ID"
    BRIDGE_GOOGLE_CLIENT_SECRET = "${local.ssm}/bridge/BRIDGE_GOOGLE_CLIENT_SECRET"
    # Entra ID: add BRIDGE_ENTRA_TENANT / _CLIENT_ID / _CLIENT_SECRET /
    # _ALLOWED_TENANTS parameters here when that upstream is registered.
  }

  alb = {
    listener_arn      = aws_lb_listener.https.arn
    security_group_id = module.network.alb_security_group_id
    host              = "sso.${var.domain}"
    priority          = 20
    health_check_path = "/healthz"
  }

  # In-flight login flows (relay.Manager.flows) and browser sessions live in
  # per-process maps, and the ALB has no stickiness: a callback landing on a
  # task that did not begin the flow fails with "link already used" on
  # 1 - 1/N of sign-ins.
  # ponytail: pin to one task; scaling out needs a shared flow/session store.
  # The pin alone is not enough: the default rolling deploy starts the
  # replacement before draining the old task, so every release would run two
  # bridges behind a non-sticky ALB. Trade a few seconds of hard downtime for
  # never serving a callback from the wrong process.
  stop_before_start = true
  desired_count     = 1
  min_count         = 1
  max_count         = 1

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# portal — public self-service identity portal (TypeScript; Postgres-backed
# job queue). Writes its mail outbox to local disk, so no read-only root.
module "portal" {
  source = "../../modules/service"

  name           = "portal"
  image          = "${aws_ecr_repository.svc["portal"].repository_url}:${var.image_tag}"
  container_port = 3000

  env = {
    PORT     = "3000"
    BASE_URL = "https://portal.${var.domain}"
    # Behind the ALB, so req.ip must come from the last X-Forwarded-For hop —
    # otherwise the rate limiter buckets every client into the balancer's IP.
    # The listener pins XFF handling (append + drop-invalid-headers).
    PORTAL_TRUST_PROXY = "1"
    # /app is root-owned in the image and the server runs as "node"; the
    # default outbox path (cwd/outbox) fails with EACCES. /tmp is writable.
    OUTBOX_DIR = "/tmp/outbox"
  }
  secrets = {
    DATABASE_URL = "${local.ssm}/portal/DATABASE_URL"
    # 32-byte base64 KEK that envelope-encrypts TOTP secrets at rest; the
    # server refuses to run against a real database without it.
    PORTAL_TOTP_KEK = "${local.ssm}/portal/PORTAL_TOTP_KEK"
  }

  readonly_root_filesystem = false

  alb = {
    listener_arn      = aws_lb_listener.https.arn
    security_group_id = module.network.alb_security_group_id
    host              = "portal.${var.domain}"
    priority          = 30
    health_check_path = "/healthz"
  }

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# console — public RBAC admin console (Go API + baked React SPA).
module "console" {
  source = "../../modules/service"

  name           = "console"
  image          = "${aws_ecr_repository.svc["console"].repository_url}:${var.image_tag}"
  container_port = 8085

  env = {
    CONSOLE_ADDR = ":8085"
    # CONSOLE_WEB_DIR=/web is baked into the image.
  }
  secrets = {
    CONSOLE_HS256_KEY = "${local.ssm}/console/CONSOLE_HS256_KEY"
  }

  alb = {
    listener_arn      = aws_lb_listener.https.arn
    security_group_id = module.network.alb_security_group_id
    host              = "console.${var.domain}"
    priority          = 40
    health_check_path = "/healthz"
  }

  # The RBAC engine and audit log are in-memory and mutated through the API,
  # so a second task would serve a divergent policy and a partial audit trail.
  # ponytail: pin to one task; scaling out needs the Postgres-backed store.
  # Same reason as bridge: without this the rolling deploy overlaps two tasks,
  # and here that means two divergent copies of the policy. The state is lost
  # on restart either way, so the drain-first outage costs nothing extra.
  stop_before_start = true
  desired_count     = 1
  min_count         = 1
  max_count         = 1

  env_name                       = local.common.env_name
  cluster_arn                    = local.common.cluster_arn
  vpc_id                         = local.common.vpc_id
  subnet_ids                     = local.common.subnet_ids
  assign_public_ip               = local.common.assign_public_ip
  service_discovery_namespace_id = local.common.service_discovery_namespace_id
  region                         = local.common.region
}

# --- Least-privilege service-to-service ingress ------------------------------
# One rule per real consumer, declared next to the wiring that motivates it.

resource "aws_vpc_security_group_ingress_rule" "keysmith_from_idp" {
  security_group_id            = module.keysmith.security_group_id
  referenced_security_group_id = module.idp.security_group_id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
  description                  = "idp signs tokens via keysmith"
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_idp" {
  security_group_id            = module.data.postgres_security_group_id
  referenced_security_group_id = module.idp.security_group_id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "idp store"
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_portal" {
  security_group_id            = module.data.postgres_security_group_id
  referenced_security_group_id = module.portal.security_group_id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "portal store + job queue"
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_sessiond" {
  security_group_id            = module.data.redis_security_group_id
  referenced_security_group_id = module.sessiond.security_group_id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  description                  = "sessiond session store"
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_keysmith" {
  security_group_id            = module.data.efs_security_group_id
  referenced_security_group_id = module.keysmith.security_group_id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
  description                  = "keysmith keystore volume"
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_sentinel" {
  security_group_id            = module.data.efs_security_group_id
  referenced_security_group_id = module.sentinel.security_group_id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
  description                  = "sentinel audit-chain volume"
}

# sessiond (8082) and sentinel (8084) currently have no in-code consumers —
# no service reads SESSIOND_* / SENTINEL_URL env vars yet. When idp adopts
# them, add the ingress pair here exactly like keysmith_from_idp.

# --- Observability ------------------------------------------------------------

module "observability" {
  source = "../../modules/observability"

  name           = local.name
  region         = var.region
  cluster_name   = aws_ecs_cluster.this.name
  alb_arn_suffix = aws_lb.this.arn_suffix
  alarm_email    = var.alarm_email

  services = {
    keysmith = { service_name = module.keysmith.service_name }
    idp      = { service_name = module.idp.service_name, alb = true, target_group_arn_suffix = module.idp.target_group_arn_suffix }
    sessiond = { service_name = module.sessiond.service_name }
    sentinel = { service_name = module.sentinel.service_name }
    bridge   = { service_name = module.bridge.service_name, alb = true, target_group_arn_suffix = module.bridge.target_group_arn_suffix }
    portal   = { service_name = module.portal.service_name, alb = true, target_group_arn_suffix = module.portal.target_group_arn_suffix }
    console  = { service_name = module.console.service_name, alb = true, target_group_arn_suffix = module.console.target_group_arn_suffix }
  }
}

# --- Cost guardrail (both environments) --------------------------------------
# A monthly cost budget so a runaway resource or a forgotten cheap-dev stack
# emails before the bill surprises you. Notifications need a subscriber, so they
# only attach when alarm_email is set; the budget itself is always visible.

resource "aws_budgets_budget" "monthly" {
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alarm_email == "" ? [] : [
      { type = "ACTUAL", threshold = 80 },
      { type = "ACTUAL", threshold = 100 },
      { type = "FORECASTED", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.alarm_email]
    }
  }
}
