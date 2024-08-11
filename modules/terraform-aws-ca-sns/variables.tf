variable "project" {
  description = "abbreviation for the project, forms the first part of the resource name"
  default     = ""
}

variable "function" {
  description = "forms the second part of the resource name"
  default     = ""
}

variable "env" {
  description = "suffix for environment, e.g. dev"
  default     = ""
}

variable "custom_sns_topic_name" {
  description = "Customised SNS topic name, leave empty to use standard naming convention"
  default     = ""
}

variable "sns_policy" {
  description = "A string containing the SNS policy, if used"
  default     = ""
}

variable "sns_policy_template" {
  description = "Name of SNS policy template file, if used"
  default     = "default"
}

variable "kms_key_arn" {
  description = "A KMS key arn to be used to encrypt the queue contents at rest"
  default     = null
}

variable "email_subscriptions" {
  type        = list(string)
  description = "List of email addresses to subscribe to this topic"
  default     = []
}

variable "lambda_subscriptions" {
  type        = map(string)
  description = "A map of lambda names to arns to subscribe to this topic"
  default     = {}
}

variable "sqs_subscriptions" {
  type        = map(string)
  description = "A map of SQS names to arns to subscribe to this topic"
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}