##### ROOT CA #####

module "kms_rsa_root_ca" {
  # Root CA private / public key pair
  source = "./modules/terraform-aws-ca-kms"

  project                  = "${var.project}-root-ca"
  env                      = var.env
  description              = "${var.project}-${var.env} Root CA key pair"
  customer_master_key_spec = var.root_ca_key_spec
  key_usage                = "SIGN_VERIFY"
  kms_policy               = "ca"
}

module "create_root_ca_iam" {
  # IAM role and policy assumed by create Root CA lambda using KMS private key
  source = "./modules/terraform-aws-ca-iam"

  project                = var.project
  env                    = var.env
  function_name          = "create-root-ca"
  kms_arn_root_ca        = module.kms_rsa_root_ca.kms_arn
  kms_arn_resource       = var.kms_arn_resource == "" ? module.kms_tls_keygen.kms_arn : var.kms_arn_resource
  ddb_table_arn          = module.dynamodb.ddb_table_arn
  policy                 = "root_ca"
  external_s3_bucket_arn = module.external_s3.s3_bucket_arn
  internal_s3_bucket_arn = module.internal_s3.s3_bucket_arn
}

module "root_crl_iam" {
  # IAM role and policy assumed by Root CA lambda using KMS private key
  source = "./modules/terraform-aws-ca-iam"

  project                = var.project
  env                    = var.env
  function_name          = "root-crl"
  kms_arn_root_ca        = module.kms_rsa_root_ca.kms_arn
  kms_arn_resource       = var.kms_arn_resource == "" ? module.kms_tls_keygen.kms_arn : var.kms_arn_resource
  ddb_table_arn          = module.dynamodb.ddb_table_arn
  policy                 = "root_crl"
  external_s3_bucket_arn = module.external_s3.s3_bucket_arn
  internal_s3_bucket_arn = module.internal_s3.s3_bucket_arn
}

module "create_rsa_root_ca_lambda" {
  # Lambda function to check for existence and otherwise create Root CA using KMS private key
  source = "./modules/terraform-aws-ca-lambda"

  project                         = var.project
  env                             = var.env
  function_name                   = "create-root-ca"
  description                     = "create Root Certificate Authority with KMS private key"
  external_s3_bucket              = module.external_s3.s3_bucket_name
  internal_s3_bucket              = module.internal_s3.s3_bucket_name
  logging_account_id              = var.logging_account_id
  subscription_filter_destination = var.subscription_filter_destination
  filter_pattern                  = var.filter_pattern
  root_ca_info                    = var.root_ca_info
  lambda_role_arn                 = module.create_root_ca_iam.lambda_role_arn
  domain                          = var.hosted_zone_domain
  runtime                         = var.runtime
  public_crl                      = var.public_crl
  sns_topic_arn                   = module.sns_ca_notifications.sns_topic_arn
}

module "rsa_root_ca_crl_lambda" {
  # Lambda function to publish Root CA CRL signed by Root CA KMS private key
  source = "./modules/terraform-aws-ca-lambda"

  project                         = var.project
  env                             = var.env
  function_name                   = "root-ca-crl"
  description                     = "publish Root CA certificate revocation list signed by KMS private key"
  external_s3_bucket              = module.external_s3.s3_bucket_name
  internal_s3_bucket              = module.internal_s3.s3_bucket_name
  logging_account_id              = var.logging_account_id
  subscription_filter_destination = var.subscription_filter_destination
  filter_pattern                  = var.filter_pattern
  root_ca_info                    = var.root_ca_info
  root_crl_days                   = var.root_crl_days
  root_crl_seconds                = var.root_crl_seconds
  lambda_role_arn                 = module.root_crl_iam.lambda_role_arn
  domain                          = var.hosted_zone_domain
  runtime                         = var.runtime
  public_crl                      = var.public_crl
  sns_topic_arn                   = module.sns_ca_notifications.sns_topic_arn
}