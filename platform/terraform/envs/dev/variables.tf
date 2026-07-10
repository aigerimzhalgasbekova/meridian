variable "region" {
  type    = string
  default = "eu-central-1"
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
