variable "name" {
  description = "Prefix for all network resources (e.g. meridian-dev)."
  type        = string
}

variable "cidr" {
  description = "VPC CIDR block."
  type        = string
  default     = "10.40.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to spread across."
  type        = number
  default     = 2
}

variable "flow_log_retention_days" {
  description = "CloudWatch Logs retention for VPC flow logs."
  type        = number
  default     = 30
}
