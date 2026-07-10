variable "name" {
  description = "Prefix (e.g. meridian-dev)."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "ephemeral" {
  description = <<-EOT
    When true (cheap/dev), the RDS instance drops deletion protection and skips
    the final snapshot so `terraform destroy` is clean for apply-demo-destroy
    cycles. Keep false (prod) to guard the database.
  EOT
  type        = bool
  default     = false
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}
