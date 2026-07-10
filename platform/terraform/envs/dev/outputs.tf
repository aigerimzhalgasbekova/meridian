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
