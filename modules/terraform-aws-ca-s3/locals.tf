resource "random_string" "suffix" {
  count = var.bucket_prefix == "" ? 1 : 0

  length  = 5
  special = false
  upper   = false
}

locals {
  cloudfront_policy    = length(var.app_aws_principals) == 0 ? "cloudfront" : "cloudfront-with-principals"
  no_cloudfront_policy = length(var.app_aws_principals) == 0 ? "secure-transport" : "secure-transport-with-principals"
  external_policy      = var.public_crl ? local.cloudfront_policy : local.no_cloudfront_policy
  internal_policy      = "secure-transport"
  bucket_policy        = contains(split("-", var.purpose), "external") ? local.external_policy : local.internal_policy
  bucket_prefix        = replace(lower(var.bucket_prefix), " ", "-")
  standard_bucket_name = local.bucket_prefix == "" ? "${var.purpose}-${var.environment}-${random_string.suffix[0].result}" : "${local.bucket_prefix}-${var.purpose}-${var.environment}"
  global_bucket_name   = local.bucket_prefix == "" ? "${var.purpose}-${random_string.suffix[0].result}" : "${local.bucket_prefix}-${var.purpose}"
  bucket_name          = var.global_bucket ? local.global_bucket_name : local.standard_bucket_name
  kms_key_alias_arn    = var.default_aws_kms_key ? null : "arn:aws:kms:eu-west-2:${data.aws_caller_identity.current.account_id}:alias/${var.kms_key_alias}"
  region               = data.aws_region.current.name
  tags = merge(var.tags, {
    Terraform = "true"
    Name      = local.bucket_name,
  })
}
