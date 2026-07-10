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
