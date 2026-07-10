terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Remote state — still local: the account exists and `terraform
  # init`/`validate`/`plan` are green against it, but the S3/DynamoDB backend
  # below is the next step before any `apply`. Create the bucket and lock table,
  # then uncomment this block and `terraform init -migrate-state` — the bootstrap
  # commands are in the platform runbook (../../README.md, step 1).
  #
  # backend "s3" {
  #   bucket         = "meridian-terraform-state"
  #   key            = "envs/dev/terraform.tfstate"
  #   region         = "eu-west-1"
  #   dynamodb_table = "meridian-terraform-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "meridian"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}
