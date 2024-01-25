variable "project" {}

variable "kms_arn_resource" {
  description = "KMS key ARN used for general resource encryption, different from key used for CA key protection"
}

variable "env" {
  description = "Environment name, e.g. dev"
}
