terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Same major as the root's committed lock. Running `terraform test` here
      # inits this directory as a root, and without a constraint that resolves
      # the latest 6.x — a second, disagreeing provider major in the same tree.
      version = "~> 5.100"
    }
  }
}
