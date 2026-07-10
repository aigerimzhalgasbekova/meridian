terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Remote state — uncomment once the bootstrap bucket/table exist.
  # Bootstrap (one-time, with admin credentials):
  #   aws s3api create-bucket --bucket meridian-terraform-state \
  #     --create-bucket-configuration LocationConstraint=eu-central-1
  #   aws s3api put-bucket-versioning --bucket meridian-terraform-state \
  #     --versioning-configuration Status=Enabled
  #   aws s3api put-public-access-block --bucket meridian-terraform-state \
  #     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  #   aws dynamodb create-table --table-name meridian-terraform-lock \
  #     --attribute-definitions AttributeName=LockID,AttributeType=S \
  #     --key-schema AttributeName=LockID,KeyType=HASH \
  #     --billing-mode PAY_PER_REQUEST
  #
  # backend "s3" {
  #   bucket         = "meridian-terraform-state"
  #   key            = "envs/dev/terraform.tfstate"
  #   region         = "eu-central-1"
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
