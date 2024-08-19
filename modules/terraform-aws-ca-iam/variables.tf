variable "project" {}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "assume_role_policy" {
  description = "Assume role policy template to use"
  default     = "lambda"
}

variable "policy" {
  description = "policy template to use"
  default     = "lambda"
}

variable "function_name" {
  description = "short name of the Lambda function without project or environment"
}

variable "kms_arn_issuing_ca" {
  description = "KMS key ARN for Issuing CA private key"
  default     = ""
}

variable "kms_arn_root_ca" {
  description = "KMS key ARN for Root CA private key"
  default     = ""
}

variable "kms_arn_tls_keygen" {
  description = "KMS key ARN for TLS certificate key generation"
  default     = ""
}

variable "kms_arn_resource" {
  description = "KMS key ARN for general resource encryption"
}

variable "ddb_table_arn" {
  description = "DynamoDB table ARN"
}

variable "external_s3_bucket_arn" {
  description = "ARN of external S3 bucket for CRL publication"
  default     = ""
}

variable "internal_s3_bucket_arn" {
  description = "ARN of external S3 bucket for CRL publication"
  default     = ""
}

variable "aws_principals" {
  description = "List of ARNs for AWS principals allowed to assume role"
  default     = []
}

variable "sns_topic_arn" {
  description = "SNS Topic ARN"
  default     = ""
}
