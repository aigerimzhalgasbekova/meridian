# Reusable ECS Fargate service: task definition (env + SSM secrets), log
# group, security group, Cloud Map DNS, optional ALB exposure, optional EFS
# mount, optional X-Ray sidecar, CPU target-tracking autoscaling.

locals {
  qualified = "${var.env_name}-${var.name}"

  app_container = merge(
    {
      name      = var.name
      image     = var.image
      essential = true
      portMappings = [{
        containerPort = var.container_port
        protocol      = "tcp"
      }]
      environment = [
        for k, v in var.env : { name = k, value = v }
      ]
      secrets = [
        for k, arn in var.secrets : { name = k, valueFrom = arn }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.region
          awslogs-stream-prefix = var.name
        }
      }
      readonlyRootFilesystem = var.readonly_root_filesystem
    },
    var.efs == null ? {} : {
      mountPoints = [{
        sourceVolume  = "data"
        containerPath = var.efs.container_path
        readOnly      = false
      }]
    }
  )

  xray_container = {
    name      = "xray-daemon"
    image     = "public.ecr.aws/xray/aws-xray-daemon:latest"
    essential = false
    portMappings = [{
      containerPort = 2000
      protocol      = "udp"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "xray"
      }
    }
  }

  containers = concat([local.app_container], var.enable_xray ? [local.xray_container] : [])
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.qualified}"
  retention_in_days = var.log_retention_days
}

# --- IAM -------------------------------------------------------------------

data "aws_iam_policy_document" "assume_ecs_tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.qualified}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Only the parameters this service declares — not /meridian/* wholesale.
data "aws_iam_policy_document" "read_secrets" {
  count = length(var.secrets) > 0 ? 1 : 0

  statement {
    actions   = ["ssm:GetParameters"]
    resources = values(var.secrets)
  }
}

resource "aws_iam_role_policy" "read_secrets" {
  count  = length(var.secrets) > 0 ? 1 : 0
  name   = "read-ssm-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.read_secrets[0].json
}

resource "aws_iam_role" "task" {
  name               = "${local.qualified}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json
}

resource "aws_iam_role_policy_attachment" "xray" {
  count      = var.enable_xray ? 1 : 0
  role       = aws_iam_role.task.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# --- Networking ------------------------------------------------------------

resource "aws_security_group" "this" {
  name        = local.qualified
  description = "${var.name} tasks"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = local.qualified }
}

# Ingress beyond the ALB (service-to-service pairs) is declared in the
# environment composition, next to the wiring that motivates it.
resource "aws_vpc_security_group_ingress_rule" "from_alb" {
  count = var.alb == null ? 0 : 1

  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = var.alb.security_group_id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
  description                  = "ALB to ${var.name}"
}

resource "aws_service_discovery_service" "this" {
  name = var.name

  dns_config {
    namespace_id   = var.service_discovery_namespace_id
    routing_policy = "MULTIVALUE"
    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# --- ALB exposure (optional) -----------------------------------------------

resource "aws_lb_target_group" "this" {
  count = var.alb == null ? 0 : 1

  name                 = local.qualified
  port                 = var.container_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 15

  health_check {
    path                = var.alb.health_check_path
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }
}

resource "aws_lb_listener_rule" "this" {
  count = var.alb == null ? 0 : 1

  listener_arn = var.alb.listener_arn
  priority     = var.alb.priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[0].arn
  }

  condition {
    host_header {
      values = [var.alb.host]
    }
  }
}

# --- Task + service --------------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  family                   = local.qualified
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode(local.containers)

  dynamic "volume" {
    for_each = var.efs == null ? [] : [var.efs]
    content {
      name = "data"
      efs_volume_configuration {
        file_system_id     = volume.value.file_system_id
        transit_encryption = "ENABLED"
        authorization_config {
          access_point_id = volume.value.access_point_id
          # ponytail: SG + access-point posix user gate access; IAM auth would
          # also need a task-role FS policy — add both together if required.
          iam = "DISABLED"
        }
      }
    }
  }
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Default (100/200) rolls start-before-stop. A service holding an exclusive
  # resource — sentinel's flock'd audit file on EFS — must deploy
  # stop-before-start (0/100): otherwise the replacement can never take the
  # lock and the deployment crash-loops while the old task stays healthy.
  deployment_minimum_healthy_percent = var.stop_before_start ? 0 : 100
  deployment_maximum_percent         = var.stop_before_start ? 100 : 200

  # stop_before_start deliberately removes the "old task keeps serving" safety
  # net, so a bad image is a hard outage that ECS retries forever. The breaker
  # puts an automatic rollback back in its place. On the 100/200 path it costs
  # nothing and still shortens a failed deploy. Requires the default ECS
  # deployment controller, which is what this module uses.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # idp migrates its schema before it can answer /healthz, and the target group
  # marks a target unhealthy ~45s after registration (15s x 3). Without a grace
  # period a slow migration — a cold RDS after resume.sh, a lock wait — gets the
  # task killed mid-migration and the replacement starts the same one over.
  # Only valid on load-balanced services; ECS rejects it otherwise.
  health_check_grace_period_seconds = var.alb == null ? null : 120

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = var.assign_public_ip
  }

  service_registries {
    registry_arn = aws_service_discovery_service.this.arn
  }

  dynamic "load_balancer" {
    for_each = var.alb == null ? [] : [1]
    content {
      target_group_arn = aws_lb_target_group.this[0].arn
      container_name   = var.name
      container_port   = var.container_port
    }
  }

  lifecycle {
    # CI deploys new task definition revisions; don't fight it on apply.
    # desired_count is runtime-owned too: autoscaling writes it continuously,
    # and scripts/pause.sh sets it to 0 — without this, the next apply silently
    # un-pauses the stack (services resume against a stopped RDS and bill).
    ignore_changes = [task_definition, desired_count]

    # An EFS-mounted task holds an exclusive file (keysmith flocks its
    # keystore, sentinel its audit chain). On the default 100/200 deploy the
    # replacement starts while the old task still holds the lock: a
    # crash-looping deploy at best, a lost write at worst. Fail the plan
    # rather than let a new EFS service be added without the pairing.
    precondition {
      condition     = var.efs == null || var.stop_before_start
      error_message = "A service mounting EFS holds an exclusive file and must set stop_before_start = true."
    }
  }
}

# --- Autoscaling ------------------------------------------------------------

resource "aws_appautoscaling_target" "this" {
  service_namespace  = "ecs"
  resource_id        = "service/${split("/", var.cluster_arn)[1]}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.min_count
  max_capacity       = var.max_count

  lifecycle {
    # scripts/pause.sh drops the floor to 0; an apply must not raise it back.
    ignore_changes = [min_capacity]
  }
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.qualified}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.this.service_namespace
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = var.cpu_target_percent
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}
