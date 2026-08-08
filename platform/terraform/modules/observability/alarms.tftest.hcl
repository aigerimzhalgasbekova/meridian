# Pins the down-detector. Every other alarm in this module watches a metric
# that stops publishing once a service reaches zero tasks, and treats missing
# data as notBreaching — so without this one a total outage resolves to OK and
# pages nobody. Run with `terraform init && terraform test` in this directory.

mock_provider "aws" {}

variables {
  name           = "meridian-test"
  region         = "eu-west-1"
  cluster_name   = "meridian-test"
  alb_arn_suffix = "app/meridian-test/0123456789abcdef"

  services = {
    idp      = { service_name = "idp", alb = true, target_group_arn_suffix = "targetgroup/meridian-test-idp/fedcba9876543210" }
    keysmith = { service_name = "keysmith" }
  }
}

run "alb_services_get_a_zero_task_down_detector" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.no_healthy_hosts["idp"].metric_name == "HealthyHostCount"
    error_message = "ALB-fronted services need a HealthyHostCount alarm: at zero registered targets every other metric here has no datapoints."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.no_healthy_hosts["idp"].treat_missing_data == "breaching"
    error_message = "no-healthy-hosts is the one alarm that must page on absent data, or the outage it exists for resolves to OK."
  }

  assert {
    condition     = !contains(keys(aws_cloudwatch_metric_alarm.no_healthy_hosts), "keysmith")
    error_message = "no-healthy-hosts is ALB-only; internal services have no target group dimension."
  }
}
