variable "bucket_prefix" {
  description = "first part of bucket name to ensure uniqueness, if left blank a random suffix will be used instead"
  default     = ""
}

variable "purpose" {
  description = "second part of bucket name"
}

variable "global_bucket" {
  description = "bucket with no environment suffix"
  default     = false
}

variable "environment" {
  description = "suffix to include in bucket name if global_bucket set to false"
  default     = "dev"
}

variable "kms_key_alias" {
  description = "KMS key alias for bucket encryption"
  default     = ""
}

variable "kms_encryption_key_arn" {
  description = "ARN of KMS encryption key used in some bucket policies"
  default     = ""
}

variable "default_aws_kms_key" {
  description = "use default AWS KMS key instead of customer managed key"
  default     = false
}

variable "sse_algorithm" {
  description = "Server side encryption algorithm, options are AES256 and aws:kms"
  default     = "aws:kms"
}

variable "server_side_encryption" {
  description = "Enable default server side encryption"
  default     = true
}

variable "bucket_key_enabled" {
  description = "Whether or not to use Amazon S3 Bucket Keys for SSE-KMS"
  default     = false
}

variable "acl" {
  description = "access control list"
  default     = "private"
}

variable "versioning" {
  description = "Enable versioning"
  default     = "Enabled"
}

variable "block_public_acls" {
  default = true
}

variable "block_public_policy" {
  default = true
}

variable "ignore_public_acls" {
  default = true
}

variable "restrict_public_buckets" {
  default = true
}

variable "access_logs" {
  description = "Enable access logs"
  default     = false
}

variable "log_bucket" {
  description = "name of log bucket if access_logs set to true"
  default     = ""
}

variable "force_destroy" {
  description = "destroy S3 bucket on Terraform destroy even with objects in bucket"
  default     = true
}

variable "object_ownership" {
  description = "manage S3 bucket ownership controls, options are BucketOwnerPreferred, ObjectWriter, BucketOwnerEnforced"
  default     = "BucketOwnerPreferred"
}

variable "oai_arn" {
  description = "ARN of CloudFront Origin Access Identity"
  default     = ""
}

variable "public_crl" {
  description = "Whether to make the CRL and CA certificates publicly available"
  default     = false
}

variable "app_aws_principals" {
  description = "List of AWS principals to allow access to CA External S3 bucket"
  type        = list(string)
  default     = []
}

variable "filter_suffix" {
  description = "Filter suffix for notifications"
  default     = ".log"
}

variable "lifecycle_policy" {
  description = "Include lifecycle policy"
  default     = false
}

variable "ia_transition" {
  description = "Days at which transition to standard IA if lifecycle policy set"
  default     = 90
}

variable "glacier_transition" {
  description = "Days at which transition to Glacier if lifecycle policy set"
  default     = 180
}

variable "noncurrent_transition" {
  description = "Days at which non current version to Glacier if lifecycle policy set"
  default     = 30
}

variable "abort_uploads" {
  description = "Days at which to abort multipart uploads if lifecycle policy set"
  default     = 2
}

variable "tags" {
  type    = map(string)
  default = {}
}

