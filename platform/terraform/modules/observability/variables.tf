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
    Per-service monitoring config. Internal services get only CPU alarms; set
    alb = true for services fronted by the ALB to add 5xx/latency/unhealthy-host
    alarms. alb (not target_group_arn_suffix) drives that selection because the
    for_each over these alarms needs keys known at plan time, and the arn suffix
    is a module output unknown until apply.
  EOT
  type = map(object({
    service_name            = string
    alb                     = optional(bool, false)
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
