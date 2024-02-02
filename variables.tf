variable "access_logs" {
  description = "Enable access logs for S3 buckets, requires log_bucket variable to be set"
  default     = false
}

variable "allow_client_keys_in_db" {
  description = "Do not change the default setting - feature will be deprecated in a future release"
  default     = false
}

variable "aws_principals" {
  description = "List of ARNs for AWS principals allowed to assume DynamoDB reader role or execute the tls_cert lambda"
  default     = []
}

variable "bucket_prefix" {
  description = "first part of s3 bucket name to ensure uniqueness, if left blank a random suffix will be used instead"
  default     = ""
}

variable "cert_info_files" {
  description = "List of file names to be uploaded to internal S3 bucket for processing"
  default     = ["tls", "revoked", "revoked-root-ca"]
}

variable "csr_files" {
  description = "List of CSR file names to be uploaded to internal S3 bucket for processing"
  default     = []
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

variable "kms_key_alias" {
  description = "KMS key alias for bucket encryption, if left at default, TLS key gen KMS key will be used"
  default     = ""
}

variable "kms_arn_resource" {
  description = "KMS key ARN used for general resource encryption, different from key used for CA key protection"
  default     = ""
}

variable "log_bucket" {
  description = "Name of log bucket, if access_logs variable set to true"
  default     = ""
}

variable "logging_account_id" {
  description = "AWS Account ID of central logging account for CloudWatch subscription filters"
  default     = ""
}

variable "memory_size" {
  description = "Standard memory allocation for Lambda functions"
  default     = 128
}

variable "memory_size_medium" {
  description = "Medium size memory for Lambda functions"
  default     = 256
}

variable "project" {
  description = "abbreviation for the project, forms first part of resource names"
  default     = "serverless"
}

variable "public_crl" {
  description = "Whether to make the CRL and CA certificates publicly available"
  default     = false
}

variable "region" {
  description = "AWS region to deploy Lambda functions"
  default     = "eu-west-2"
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

variable "runtime" {
  description = "Lambda language runtime"
  default     = "python3.12"

  validation {
    condition = contains([
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

variable "subscription_filter_destination" {
  description = "CloudWatch log subscription filter destination, last section of ARN"
  default     = ""
}

variable "timeout" {
  description = "Amount of time Lambda Function has to run in seconds"
  default     = 180
}
