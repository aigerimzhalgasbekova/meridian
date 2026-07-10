output "postgres_endpoint" {
  value = aws_db_instance.postgres.address
}

output "postgres_security_group_id" {
  value = aws_security_group.postgres.id
}

output "postgres_master_secret_arn" {
  description = "AWS-managed master password secret (bootstrap runbook input)."
  value       = aws_db_instance.postgres.master_user_secret[0].secret_arn
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_security_group_id" {
  value = aws_security_group.redis.id
}

output "efs_file_system_id" {
  value = aws_efs_file_system.this.id
}

output "efs_security_group_id" {
  value = aws_security_group.efs.id
}

output "efs_access_point_keysmith" {
  value = aws_efs_access_point.keysmith.id
}

output "efs_access_point_sentinel" {
  value = aws_efs_access_point.sentinel.id
}
