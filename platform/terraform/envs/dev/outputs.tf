output "alb_dns_name" {
  description = "Point idp/sso/portal/console.<domain> CNAMEs here."
  value       = aws_lb.this.dns_name
}

output "ecr_repository_urls" {
  value = { for k, r in aws_ecr_repository.svc : k => r.repository_url }
}

output "postgres_endpoint" {
  value = module.data.postgres_endpoint
}

output "postgres_master_secret_arn" {
  description = "Read this to bootstrap per-service DB users (runbook step 2)."
  value       = module.data.postgres_master_secret_arn
}

output "redis_endpoint" {
  value = module.data.redis_endpoint
}

output "alarms_sns_topic" {
  value = module.observability.sns_topic_arn
}

# Runbook step 5 runs one throwaway task off the existing portal task
# definition to create the portal database; run-task needs the network config
# the ECS service normally supplies from state.
output "portal_run_task_network" {
  description = "--network-configuration argument for the runbook step 5 `aws ecs run-task`."
  value = jsonencode({
    awsvpcConfiguration = {
      subnets        = local.common.subnet_ids
      securityGroups = [module.portal.security_group_id]
      assignPublicIp = local.common.assign_public_ip ? "ENABLED" : "DISABLED"
    }
  })
}
