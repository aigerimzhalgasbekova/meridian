terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Remote state. The bucket name carries the account id because S3 names are
  # global — the bare name was already taken (runbook step 1).
  backend "s3" {
    bucket         = "meridian-terraform-state-123456789012"
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
