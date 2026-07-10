variable "name" {
  description = "Prefix (e.g. meridian-dev)."
  type        = string
}

variable "region" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "alb_arn_suffix" {
  description = "arn_suffix of the shared ALB (metric dimension)."
  type        = string
}

variable "services" {
  description = <<-EOT
    Per-service monitoring config. target_group_arn_suffix is null for
    internal services (no ALB metrics; they still get CPU alarms).
  EOT
  type = map(object({
    service_name            = string
    target_group_arn_suffix = optional(string)
  }))
}

variable "alarm_email" {
  description = "Email for SNS alarm subscription; empty skips the subscription."
  type        = string
  default     = ""
}

variable "p99_latency_threshold_seconds" {
  type    = number
  default = 1.5
}

variable "five_xx_threshold_per_5m" {
  type    = number
  default = 10
}
