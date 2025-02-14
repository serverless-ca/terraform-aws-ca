variable "allowed_invocation_principals" {
  description = "List of principals allowed to invoke this lambda"
  default     = []
}

variable "enable_subscription_filters" {
  description = "Enable CloudWatch logs Subscription filters for CA Lambda functions"
  default     = false
}

variable "description" {
  description = "description of Lambda function purpose"
}

variable "domain" {
  description = "Hosted zone domain, e.g. dev.ca.example.com"
}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "prod_envs" {
  description = "List of production environment names. Used to define resource name suffix"
  default     = ["prd", "prod"]
}

variable "external_s3_bucket" {
  description = "External S3 Bucket Name"
}

variable "filter_pattern" {
  description = "Filter pattern for CloudWatch logs subscription filter"
}

variable "function_name" {
  description = "short name of the Lambda function without project or environment"
}

variable "internal_s3_bucket" {
  description = "Internal S3 Bucket Name"
}

variable "issuing_ca_info" {
  description = "Issuing CA information"
  default     = {}
}

variable "issuing_crl_days" {
  description = "Number of days before Issuing CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
}

variable "issuing_crl_seconds" {
  description = "Number of seconds before Issuing CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
}

variable "lambda_role_arn" {
  description = "Lambda role ARN"
}

variable "logging_account_id" {
  description = "AWS Account ID of central logging account for CloudWatch subscription filters"
  default     = ""
}

variable "max_cert_lifetime" {
  description = "Maximum end entity certificate lifetime in days"
  default     = 365
}

variable "memory_size" {
  description = "Memory allocation for scanning Lambda functions"
  default     = 128
}

variable "platform" {
  description = "ManyLinux platform version, needed to avoid glibc errors due to incompatible versions"
  default     = "manylinux2014_x86_64"
}

variable "project" {
  description = "abbreviation for the project, forms first part of resource names"
  default     = "secure-email"
}

variable "public_crl" {
  description = "Whether to make the CRL and CA certificates publicly available"
  default     = false
}

variable "retention_in_days" {
  description = "CloudWatch log group retention in days"
  default     = 30
}

variable "root_ca_info" {
  description = "Root CA information"
  default     = {}
}

variable "root_crl_days" {
  description = "Number of days before Root CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
}

variable "root_crl_seconds" {
  description = "Number of seconds before Root CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
}

variable "runtime" {
  description = "Lambda language runtime"
}

variable "sns_topic_arn" {
  description = "SNS Topic ARN for Lambda function to publish to"
}

variable "subscription_filter_destination" {
  description = "CloudWatch log subscription filter destination, last section of ARN"
  default     = ""
}

variable "timeout" {
  description = "Amount of time Lambda Function has to run in seconds"
  default     = 180
}
