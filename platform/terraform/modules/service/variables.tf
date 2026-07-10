variable "name" {
  description = "Service name (e.g. idp). Used for the ECS service, log group, DNS."
  type        = string
}

variable "env_name" {
  description = "Environment prefix (e.g. meridian-dev)."
  type        = string
}

variable "cluster_arn" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Subnets the tasks run in. Private (with NAT) normally; the public subnets in cheap/no-NAT dev, paired with assign_public_ip = true."
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Give tasks a public IP for egress when there is no NAT gateway. Ingress is still gated entirely by the task security group."
  type        = bool
  default     = false
}

variable "image" {
  description = "Full image reference (ECR repo URL + tag)."
  type        = string
}

variable "container_port" {
  type = number
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 256
}

variable "memory" {
  description = "Fargate task memory (MiB)."
  type        = number
  default     = 512
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "min_count" {
  type    = number
  default = 1
}

variable "max_count" {
  type    = number
  default = 3
}

variable "cpu_target_percent" {
  description = "Target-tracking autoscaling threshold on average CPU."
  type        = number
  default     = 60
}

variable "env" {
  description = "Plain environment variables."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Env vars sourced from SSM Parameter Store: name => parameter ARN."
  type        = map(string)
  default     = {}
}

variable "alb" {
  description = <<-EOT
    Set to expose the service on the shared ALB via host-based routing;
    null keeps the service internal (Cloud Map DNS only).
  EOT
  type = object({
    listener_arn      = string
    security_group_id = string
    host              = string
    priority          = number
    health_check_path = string
  })
  default = null
}

variable "service_discovery_namespace_id" {
  description = "Cloud Map private DNS namespace for service-to-service calls."
  type        = string
}

variable "efs" {
  description = "Optional EFS mount (keysmith keystore, sentinel audit chain)."
  type = object({
    file_system_id  = string
    access_point_id = string
    container_path  = string
  })
  default = null
}

variable "enable_xray" {
  description = "Run the X-Ray daemon sidecar. Off until services emit traces (see docs/observability.md)."
  type        = bool
  default     = false
}

variable "readonly_root_filesystem" {
  description = "Distroless services default to a read-only root; portal writes its mail outbox to disk and opts out."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "region" {
  type = string
}

variable "stop_before_start" {
  description = "Deploy 0/100 (stop old task before starting new). Required when the task holds an exclusive resource, e.g. a flock'd file on EFS."
  type        = bool
  default     = false
}
