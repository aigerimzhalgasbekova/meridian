# Stateful backends: one small RDS Postgres (databases: idp, portal), one
# single-node ElastiCache Redis (sessiond), one EFS filesystem with per-service
# access points (keysmith keystore, sentinel audit chain). Everything
# encrypted, nothing publicly reachable; ingress rules are declared in the
# environment composition next to the consuming service.

# --- RDS Postgres ------------------------------------------------------------

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "postgres" {
  name        = "${var.name}-postgres"
  description = "RDS Postgres; ingress granted per consuming service"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-postgres" }
}

resource "aws_db_instance" "postgres" {
  identifier     = "${var.name}-postgres"
  engine         = "postgres"
  engine_version = "17"
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "idp" # the portal database is created in the bootstrap runbook
  username = "meridian"
  # Master password lives in AWS-managed Secrets Manager — never in state,
  # tfvars, or CI. The runbook derives per-service DSNs from it and writes
  # them to SSM Parameter Store.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.postgres.id]
  publicly_accessible    = false
  multi_az               = false # dev cost trade-off; flip for prod

  backup_retention_period   = 7
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-postgres-final"

  performance_insights_enabled = false
}

# --- ElastiCache Redis -------------------------------------------------------

resource "aws_elasticache_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "redis" {
  name        = "${var.name}-redis"
  description = "ElastiCache Redis; ingress granted per consuming service"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-redis" }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "${var.name}-redis"
  description          = "sessiond session store + revocation pub/sub"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = var.redis_node_type

  num_cache_clusters         = 1 # dev cost trade-off; >=2 + failover for prod
  automatic_failover_enabled = false

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true # sessiond connects with rediss://

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.redis.id]
}

# --- EFS (keysmith keystore, sentinel audit chain) ---------------------------

resource "aws_efs_file_system" "this" {
  creation_token = "${var.name}-data"
  encrypted      = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = { Name = "${var.name}-data" }
}

resource "aws_security_group" "efs" {
  name        = "${var.name}-efs"
  description = "EFS mount targets; ingress granted per consuming service"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-efs" }
}

resource "aws_efs_mount_target" "this" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

# Distroless images run as uid/gid 65532 (nonroot).
resource "aws_efs_access_point" "keysmith" {
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/keysmith"
    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "700"
    }
  }

  tags = { Name = "${var.name}-keysmith" }
}

resource "aws_efs_access_point" "sentinel" {
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/sentinel"
    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "700"
    }
  }

  tags = { Name = "${var.name}-sentinel" }
}
