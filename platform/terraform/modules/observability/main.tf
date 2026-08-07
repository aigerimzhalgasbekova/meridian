# CloudWatch dashboard + alarms -> SNS. ALB metrics (latency, 5xx, healthy
# hosts) for exposed services; ECS CPU for everything.

locals {
  alb_services = { for k, v in var.services : k => v if v.alb }

  dashboard_widgets = concat(
    [
      for i, k in sort(keys(local.alb_services)) : {
        type   = "metric"
        x      = 0
        y      = i * 6
        width  = 12
        height = 6
        properties = {
          title  = "${k} — p99 latency & 5xx"
          region = var.region
          stat   = "p99"
          period = 60
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_arn_suffix, "TargetGroup", local.alb_services[k].target_group_arn_suffix],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", var.alb_arn_suffix, "TargetGroup", local.alb_services[k].target_group_arn_suffix, { stat = "Sum", yAxis = "right" }],
          ]
        }
      }
    ],
    [
      for i, k in sort(keys(var.services)) : {
        type   = "metric"
        x      = 12
        y      = i * 6
        width  = 12
        height = 6
        properties = {
          title  = "${k} — CPU"
          region = var.region
          stat   = "Average"
          period = 60
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.cluster_name, "ServiceName", var.services[k].service_name],
          ]
        }
      }
    ]
  )
}

resource "aws_sns_topic" "alarms" {
  name = "${var.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name
  dashboard_body = jsonencode({ widgets = local.dashboard_widgets })
}

resource "aws_cloudwatch_metric_alarm" "five_xx" {
  for_each = local.alb_services

  alarm_name          = "${var.name}-${each.key}-5xx"
  alarm_description   = "${each.key}: elevated 5xx from targets"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.five_xx_threshold_per_5m
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = each.value.target_group_arn_suffix
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  for_each = local.alb_services

  alarm_name          = "${var.name}-${each.key}-unhealthy-hosts"
  alarm_description   = "${each.key}: target failing ALB health checks"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = each.value.target_group_arn_suffix
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}

# The other alarms all watch metrics that only exist while a task is
# registered, and treat missing data as OK — so a service at zero tasks goes
# completely quiet. HealthyHostCount is the one signal that stays meaningful
# there, and it is the only alarm that must treat missing data as breaching.
# scripts/pause.sh disables/re-enables just these while the stack is parked.
# ponytail: covers ALB-fronted services only. The internal three (keysmith,
# sessiond, sentinel) would need ECS/ContainerInsights RunningTaskCount, which
# the cheap profile does not publish — add it when Insights is on in prod, or
# an EventBridge rule on ECS task state change if it is needed in dev.
resource "aws_cloudwatch_metric_alarm" "no_healthy_hosts" {
  for_each = local.alb_services

  alarm_name          = "${var.name}-${each.key}-no-healthy-hosts"
  alarm_description   = "${each.key}: zero healthy targets (service is down)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = each.value.target_group_arn_suffix
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  lifecycle {
    # pause.sh disables the actions out-of-band; actions_enabled defaults to
    # true, so without this an unrelated apply re-arms them mid-pause and every
    # down-detector pages continuously. Same reason desired_count/min_capacity
    # are ignored in modules/service.
    ignore_changes = [actions_enabled]
  }
}

resource "aws_cloudwatch_metric_alarm" "p99_latency" {
  for_each = local.alb_services

  alarm_name          = "${var.name}-${each.key}-p99-latency"
  alarm_description   = "${each.key}: p99 latency above threshold"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  extended_statistic  = "p99"
  period              = 300
  evaluation_periods  = 2
  threshold           = var.p99_latency_threshold_seconds
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = each.value.target_group_arn_suffix
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "cpu" {
  for_each = var.services

  alarm_name          = "${var.name}-${each.key}-cpu"
  alarm_description   = "${each.key}: sustained high CPU (autoscaling ceiling?)"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = var.cluster_name
    ServiceName = each.value.service_name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}
