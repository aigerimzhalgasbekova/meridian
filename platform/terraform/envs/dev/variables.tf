variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "environment" {
  description = <<-EOT
    Environment name. "prod" keeps the hardened set: RDS deletion protection +
    final snapshot, WAF on the ALB, Container Insights, and a NAT gateway. Any
    other value (e.g. "dev") runs cheap and ephemeral — no NAT (tasks in public
    subnets), no WAF, no Container Insights, and a destroy-clean database — so
    you can apply-demo-destroy on credits. A budget guardrail is created either way.
  EOT
  type        = string
  default     = "dev"
}

variable "monthly_budget_usd" {
  description = "AWS Budgets monthly cost limit. Alerts fire at 80%/100% actual and 100% forecast when alarm_email is set."
  type        = number
  default     = 200
}

variable "domain" {
  description = "Base domain for public services (idp.<domain>, sso.<domain>, portal.<domain>, console.<domain>)."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate covering *.<domain> in this region."
  type        = string
}

variable "image_tag" {
  description = "Image tag the task definitions reference (release.yml pushes it)."
  type        = string
  default     = "dev"
}

variable "alarm_email" {
  description = "Email for CloudWatch alarm notifications; empty = no subscription."
  type        = string
  default     = ""
}
