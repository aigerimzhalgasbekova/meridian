output "security_group_id" {
  value = aws_security_group.this.id
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "target_group_arn_suffix" {
  value = var.alb == null ? null : aws_lb_target_group.this[0].arn_suffix
}

output "dns_name" {
  description = "Cloud Map name inside the VPC (append the namespace)."
  value       = aws_service_discovery_service.this.name
}

output "task_role_name" {
  description = "Task role, for attaching service-specific runtime policies in the composition."
  value       = aws_iam_role.task.name
}
