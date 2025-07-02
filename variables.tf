variable "access_logs" {
  type        = bool
  description = "Enable access logs for S3 buckets, requires log_bucket variable to be set"
  default     = false
}

variable "additional_dynamodb_tags" {
  type        = map(string)
  description = "Tags added to DynamoDB tables, merged with default tags"
  default     = {}
}

variable "additional_lambda_tags" {
  type        = map(string)
  description = "Tags added to Lambda functions, merged with default tags"
  default     = {}
}

variable "additional_s3_tags" {
  type        = map(string)
  description = "Tags added to S3 buckets, merged with default tags"
  default     = {}
}

variable "aws_principals" {
  type        = list(string)
  description = "List of ARNs for AWS principals allowed to assume DynamoDB reader role or execute the tls_cert lambda"
  default     = []
}

variable "bucket_prefix" {
  type        = string
  description = "First part of s3 bucket name to ensure uniqueness, if left blank a random suffix will be used instead"
  default     = ""
}

variable "cert_info_files" {
  type        = list(string)
  description = "List of file names to be uploaded to internal S3 bucket for processing"
  default     = [] # To enable certificate revocation change to ["tls", "revoked", "revoked-root-ca"] 
}

variable "csr_files" {
  type        = list(string)
  description = "List of CSR file names to be uploaded to internal S3 bucket for processing"
  default     = []
}

variable "cloudfront_web_acl_id" {
  type        = string
  description = "WAF attachment for the public CRL Cloudfront distribution, expects the WAF ARN"
  default     = null
}

variable "custom_sns_topic_display_name" {
  type        = string
  description = "Customised SNS topic display name, leave empty to use standard naming convention"
  default     = ""
}

variable "custom_sns_topic_name" {
  type        = string
  description = "Customised SNS topic name, leave empty to use standard naming convention"
  default     = ""
}

variable "env" {
  type        = string
  description = "Environment name, e.g. dev"
  default     = "dev"
}

variable "filter_pattern" {
  type        = string
  description = "Filter pattern for CloudWatch logs subscription filter"
  default     = ""
}

variable "hosted_zone_domain" {
  type        = string
  description = "Hosted zone domain, e.g. dev.ca.example.com"
  default     = ""
}

variable "hosted_zone_id" {
  type        = string
  description = "Hosted zone ID for public zone, e.g. Z0123456XXXXXXXXXXX"
  default     = ""
}

variable "issuing_ca_info" {
  type = object({
    commonName           = string
    country              = optional(string)
    state                = optional(string)
    lifetime             = optional(number)
    locality             = optional(string)
    organization         = optional(string)
    organizationalUnit   = optional(string)
    emailAddress         = optional(string)
    pathLengthConstraint = optional(number)
  })

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
}

variable "issuing_ca_key_spec" {
  type        = string
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
  type        = number
  description = "Number of days before Issuing CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
}

variable "issuing_crl_seconds" {
  type        = number
  description = "Number of seconds before Issuing CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
}

variable "kms_key_alias" {
  type        = string
  description = "KMS key alias for bucket encryption with key rotation disabled, if left at default, TLS key gen KMS key will be used"
  default     = ""
}

variable "kms_arn_resource" {
  type        = string
  description = "KMS key ARN used for general resource encryption, different from key used for CA key protection"
  default     = ""
}

variable "default_aws_kms_key_for_s3" {
  type        = bool
  description = "Use default AWS KMS key instead of customer managed key for S3 bucket encryption. Applicable only if \"sse_algorithm\" is \"aws:kms\""
  default     = false
}

variable "bucket_key_enabled" {
  type        = bool
  description = "Whether or not to use Amazon S3 Bucket Keys for SSE-KMS"
  default     = false
}

variable "log_bucket" {
  type        = string
  description = "Name of log bucket, if access_logs variable set to true"
  default     = ""
}

variable "logging_account_id" {
  type        = string
  description = "AWS Account ID of central logging account for CloudWatch subscription filters"
  default     = ""
}

variable "max_cert_lifetime" {
  type        = number
  description = "Maximum end entity certificate lifetime in days"
  default     = 365
}

variable "memory_size" {
  type        = number
  description = "Standard memory allocation for Lambda functions"
  default     = 128
}

variable "prod_envs" {
  type        = list(string)
  description = "List of production environment names, for these names the environment name suffix is not required in resource names"
  default     = ["prd", "prod"]
}

variable "project" {
  type        = string
  description = "abbreviation for the project, forms first part of resource names"
  default     = "serverless"
}

variable "public_crl" {
  type        = bool
  description = "Whether to make the CRL and CA certificates publicly available"
  default     = false
}

variable "root_ca_info" {
  type = object({
    commonName           = string
    country              = optional(string)
    state                = optional(string)
    lifetime             = optional(number)
    locality             = optional(string)
    organization         = optional(string)
    organizationalUnit   = optional(string)
    emailAddress         = optional(string)
    pathLengthConstraint = optional(number)
  })

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
}

variable "root_ca_key_spec" {
  type        = string
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
  type        = number
  description = "Number of days before Root CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval"
  default     = 1
}

variable "root_crl_seconds" {
  type        = number
  description = "Number of seconds before Root CA CRL expires, in addition to days. Used for overlap in case of clock skew"
  default     = 600
}

variable "runtime" {
  type        = string
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
  type        = list(string)
  description = "List of AWS Principals to allow access to external S3 bucket"
  default     = []
}

variable "schedule_expression" {
  type        = string
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
  type        = string
  description = "A string containing the SNS policy, if used"
  default     = ""
}

variable "sns_policy_template" {
  type        = string
  description = "Name of SNS policy template file, if used"
  default     = "default"
}

variable "sns_sqs_subscriptions" {
  type        = map(string)
  description = "A map of SQS names to arns to subscribe to the SNS topic"
  default     = {}
}

variable "subscription_filter_destination" {
  type        = string
  description = "CloudWatch log subscription filter destination, last section of ARN"
  default     = ""
}

# see also additional_s3_tags, additional_dynamodb_tags, additional_lambda_tags
variable "tags" {
  type    = map(string)
  default = {}
}

variable "timeout" {
  type        = number
  description = "Amount of time Lambda Function has to run in seconds"
  default     = 180
}

variable "xray_enabled" {
  type        = bool
  description = "Whether to enable active tracing with AWS X-Ray"
  default     = true
}
