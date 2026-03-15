variable "project" {}

variable "env" {}

variable "purpose" {
  description = "Purpose of secret, forms part of resource name"
}

variable "description" {
  description = "Description of secret"
  default     = ""
}

variable "kms_key_id" {
  description = "KMS key ID to encrypt the secret"
  default     = ""
}

variable "ignore_value_changes" {
  description = "Whether to ignore changes to secret value"
  type        = bool
  default     = true
}

variable "value" {
  description = "Secret value"
  default     = "dummy-value"
  sensitive   = true
}

variable "tags" {
  type    = map(any)
  default = {}
}

variable "recovery_window_in_days" {
  description = "Number of days that AWS Secrets Manager waits before deleting the secret"
  type        = number
  default     = 7
}
