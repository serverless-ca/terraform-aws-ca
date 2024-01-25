variable "project" {
  description = "abbreviation for the project, forms first part of resource names"
}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "kms_arn" {}

variable "role_arn" {
  description = "IAM role to be assumed by state machine"
}

variable "retention_in_days" {
  description = "specifies the number of days you want to retain log events"
  default     = 365
}

variable "purpose" {
  description = "purpose of Step Function"
  default     = "ca"
}

variable "internal_s3_bucket" {
  description = "Internal S3 Bucket Name"
}
