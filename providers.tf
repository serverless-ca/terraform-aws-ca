terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.22" # blocked_encryption_types added in AWS provider 6.22.0
    }
  }
}
