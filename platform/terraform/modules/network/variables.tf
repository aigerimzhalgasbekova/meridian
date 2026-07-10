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

variable "enable_nat" {
  description = <<-EOT
    Provision a NAT gateway so private-subnet workloads have egress. Disable
    (cheap dev) to run Fargate tasks in the public subnets with public IPs
    instead — their security groups still block all internet ingress, and this
    drops the single largest idle cost (~$32/mo).
  EOT
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "CloudWatch Logs retention for VPC flow logs."
  type        = number
  default     = 30
}
