variable "access_logs" {
  description = "Enable access logs for S3 buckets, requires log_bucket variable to be set"
  default     = false
}

variable "aws_principals" {
  description = "List of ARNs for AWS principals allowed to assume DynamoDB reader role or execute the tls_cert lambda"
  default     = []
}

variable "bucket_prefix" {
  description = "First part of s3 bucket name to ensure uniqueness, if left blank a random suffix will be used instead"
  default     = ""
}

variable "cert_info_files" {
  description = "List of file names to be uploaded to internal S3 bucket for processing"
  default     = [] # To enable certificate revocation change to ["tls", "revoked", "revoked-root-ca"]
  type        = list(string)
}

variable "csr_files" {
  description = "List of CSR file names to be uploaded to internal S3 bucket for processing"
  default     = []
  type        = list(string)
}

variable "custom_sns_topic_display_name" {
  description = "Customised SNS topic display name, leave empty to use standard naming convention"
  default     = ""
}

variable "custom_sns_topic_name" {
  description = "Customised SNS topic name, leave empty to use standard naming convention"
  default     = ""
}

variable "env" {
  description = "Environment name, e.g. dev"
  default     = "dev"
}

variable "filter_pattern" {
  description = "Filter pattern for CloudWatch logs subscription filter"
  default     = ""
}

variable "hosted_zone_domain" {
  description = "Hosted zone domain, e.g. dev.ca.example.com"
  default     = ""
}

variable "hosted_zone_id" {
  description = "Hosted zone ID for public zone, e.g. Z0123456XXXXXXXXXXX"
  default     = ""
}

variable "issuing_ca_info" {
  description = "Issuing CA certificate information"
  default = {
    country              = "GB"
    state                = "London"
    lifetime             = 3650
    locality             = "London"
    organization         = "Serverless"
    organizationalUnit   = "IT"
    commonName           = "Serverless Issuing CA"
    emailAddress         = null
    pathLengthConstraint = null
  }
  type = object({
    country              = string
    state                = optional(string)
    lifetime             = number
    locality             = optional(string)
    organization         = string
    organizationalUnit   = optional(string)
    commonName           = string
    emailAddress         = optional(string, null)
    pathLengthConstraint = optional(number, null)
  })
}

variable "issuing_ca_key_spec" {
  description = "Issuing CA key specification"
  default     = "ECC_NIST_P256"

  validation {
    condition = contains([
      "RSA_2048",
      "RSA_3072",
      "RSA_4096",
      "ECC_NIST_P256",
      "ECC_NIST_P384",
      "ECC_NIST_P521",
    ], var.issuing_ca_key_spec)
    error_message = "Invalid issuing_ca_key_spec"
  }
}

variable "issuing_crl_days" {
  description = "Number of days before Issuing CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
  type        = number
}

variable "issuing_crl_seconds" {
  description = "Number of seconds before Issuing CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
  type        = number
}

variable "kms_key_alias" {
  description = "KMS key alias for bucket encryption with key rotation disabled, if left at default, TLS key gen KMS key will be used"
  default     = ""
}

variable "kms_arn_resource" {
  description = "KMS key ARN used for general resource encryption, different from key used for CA key protection"
  default     = ""
}

variable "default_aws_kms_key_for_s3" {
  description = "Use default AWS KMS key instead of customer managed key for S3 bucket encryption. Applicable only if \"sse_algorithm\" is \"aws:kms\""
  default     = false
}

variable "bucket_key_enabled" {
  description = "Whether or not to use Amazon S3 Bucket Keys for SSE-KMS"
  default     = false
}

variable "log_bucket" {
  description = "Name of log bucket, if access_logs variable set to true"
  default     = ""
}

variable "logging_account_id" {
  description = "AWS Account ID of central logging account for CloudWatch subscription filters"
  default     = ""
}

variable "max_cert_lifetime" {
  description = "Maximum end entity certificate lifetime in days"
  default     = 365
  type        = number
}

variable "memory_size" {
  description = "Standard memory allocation for Lambda functions"
  default     = 128
  type        = number
}

variable "prod_envs" {
  description = "List of production environment names, for these names the environment name suffix is not required in resource names"
  default     = ["prd", "prod"]
  type        = list(string)
}

variable "project" {
  description = "abbreviation for the project, forms first part of resource names"
  default     = "serverless"
}

variable "public_crl" {
  description = "Whether to make the CRL and CA certificates publicly available"
  default     = false
}

variable "root_ca_info" {
  description = "Root CA certificate information"
  default = {
    country              = "GB"
    state                = "London"
    lifetime             = 7300
    locality             = "London"
    organization         = "Serverless"
    organizationalUnit   = "IT"
    commonName           = "Serverless Root CA"
    emailAddress         = null
    pathLengthConstraint = null
  }
  type = object({
    country              = string
    state                = optional(string)
    lifetime             = number
    locality             = optional(string)
    organization         = string
    organizationalUnit   = optional(string)
    commonName           = string
    emailAddress         = optional(any)
    pathLengthConstraint = any
  })
}

variable "root_ca_key_spec" {
  description = "Root CA key specification"
  default     = "ECC_NIST_P384"

  validation {
    condition = contains([
      "RSA_2048",
      "RSA_3072",
      "RSA_4096",
      "ECC_NIST_P256",
      "ECC_NIST_P384",
      "ECC_NIST_P521",
    ], var.root_ca_key_spec)
    error_message = "Invalid root_ca_key_spec"
  }
}

variable "root_crl_days" {
  description = "Number of days before Root CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
  type        = number
}

variable "root_crl_seconds" {
  description = "Number of seconds before Root CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
  type        = number
}

variable "runtime" {
  description = "Lambda language runtime"
  default     = "python3.13"

  validation {
    condition = contains([
      "python3.13",
      "python3.12",
      "python3.11",
      "python3.10",
    ], var.runtime)
    error_message = "Invalid Python version"
  }
}

variable "s3_aws_principals" {
  description = "List of AWS Principals to allow access to external S3 bucket"
  default     = []
}

variable "schedule_expression" {
  description = "Step function schedule in cron format, interval should normally be the same as issuing_crl_days"
  default     = "cron(15 8 * * ? *)" # 8.15 a.m. daily
}

variable "sns_email_subscriptions" {
  type        = list(string)
  description = "List of email addresses to subscribe to SNS topic"
  default     = []
}

variable "sns_lambda_subscriptions" {
  type        = map(string)
  description = "A map of lambda names to arns to subscribe to SNS topic"
  default     = {}
}

variable "sns_policy" {
  description = "A string containing the SNS policy, if used"
  default     = ""
}

variable "sns_policy_template" {
  description = "Name of SNS policy template file, if used"
  default     = "default"
}

variable "sns_sqs_subscriptions" {
  type        = map(string)
  description = "A map of SQS names to arns to subscribe to thSNSis topic"
  default     = {}
}

variable "subscription_filter_destination" {
  description = "CloudWatch log subscription filter destination, last section of ARN"
  default     = ""
}

variable "timeout" {
  description = "Amount of time Lambda Function has to run in seconds"
  default     = 180
  type        = number
}

variable "xray_enabled" {
  description = "Whether to enable active tracing with AWS X-Ray"
  default     = true
}

