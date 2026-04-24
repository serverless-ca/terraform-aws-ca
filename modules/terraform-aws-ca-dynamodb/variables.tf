variable "project" {}

variable "kms_arn_resource" {
  description = "KMS key ARN used for general resource encryption, different from key used for CA key protection"
}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Enable deletion protection for the DynamoDB table"
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}