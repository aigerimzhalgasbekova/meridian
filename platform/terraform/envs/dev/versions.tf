terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Remote state, partial configuration: the bucket name carries the account id
  # (S3 names are global — the bare name was already taken), so it lives in a
  # gitignored backend.hcl rather than here. See backend.hcl.example and
  # runbook step 1: terraform init -backend-config=backend.hcl
  backend "s3" {
    key            = "envs/dev/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "meridian-terraform-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "meridian"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
