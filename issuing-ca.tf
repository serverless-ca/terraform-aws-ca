module "kms_rsa_issuing_ca" {
  # Issuing CA private / public key pair
  source = "./modules/terraform-aws-ca-kms"

  for_each                 = var.issuing_ca_list
  project                  = "${var.project}-${each.key}-ca"
  env                      = var.env
  description              = "${var.project}-${var.env} Issuing CA key pair for ${each.key}"
  customer_master_key_spec = var.issuing_ca_key_spec
  key_usage                = "SIGN_VERIFY"
  kms_policy               = "ca"
}

module "create_issuing_ca_iam" {
  # IAM role and policy assumed by create Issuing CA lambda using KMS private key
  source = "./modules/terraform-aws-ca-iam"

  project                = var.project
  env                    = var.env
  function_name          = "create-issuing-ca"
  kms_arn_ca_list        = concat([module.kms_rsa_root_ca.kms_arn], [for ca_name, _ in var.issuing_ca_list : module.kms_rsa_issuing_ca[ca_name].kms_arn])
  kms_arn_resource       = var.kms_arn_resource == "" ? module.kms_tls_keygen.kms_arn : var.kms_arn_resource
  ddb_table_arn          = module.dynamodb.ddb_table_arn
  policy                 = "issuing_ca"
  external_s3_bucket_arn = module.external_s3.s3_bucket_arn
  internal_s3_bucket_arn = module.internal_s3.s3_bucket_arn
}

module "issuing_crl_iam" {
  # IAM role and policy assumed by Issuing CA lambda using KMS private key
  source = "./modules/terraform-aws-ca-iam"

  project                = var.project
  env                    = var.env
  function_name          = "issuing-crl"
  kms_arn_ca_list        = [for ca_name, _ in var.issuing_ca_list : module.kms_rsa_issuing_ca[ca_name].kms_arn]
  kms_arn_resource       = var.kms_arn_resource == "" ? module.kms_tls_keygen.kms_arn : var.kms_arn_resource
  ddb_table_arn          = module.dynamodb.ddb_table_arn
  policy                 = "issuing_crl"
  external_s3_bucket_arn = module.external_s3.s3_bucket_arn
  internal_s3_bucket_arn = module.internal_s3.s3_bucket_arn
}

module "tls_keygen_iam" {
  # IAM role and policy assumed by TLS certificate lambda using issuing CA KMS private key
  source = "./modules/terraform-aws-ca-iam"

  project                = var.project
  env                    = var.env
  function_name          = "tls-cert"
  kms_arn_ca_list        = [for ca_name, _ in var.issuing_ca_list : module.kms_rsa_issuing_ca[ca_name].kms_arn]
  kms_arn_tls_keygen     = module.kms_tls_keygen.kms_arn
  kms_arn_resource       = var.kms_arn_resource == "" ? module.kms_tls_keygen.kms_arn : var.kms_arn_resource
  ddb_table_arn          = module.dynamodb.ddb_table_arn
  policy                 = "tls_cert"
  external_s3_bucket_arn = module.external_s3.s3_bucket_arn
  internal_s3_bucket_arn = module.internal_s3.s3_bucket_arn
  sns_topic_arn          = module.sns_ca_notifications.sns_topic_arn
}

module "create_rsa_issuing_ca_lambda" {
  # Lambda function to check for existence and otherwise create Issuing CA using KMS private key
  source = "./modules/terraform-aws-ca-lambda"

  project                         = var.project
  env                             = var.env
  function_name                   = "create-issuing-ca"
  description                     = "create Issuing Certificate Authority with KMS private key"
  external_s3_bucket              = module.external_s3.s3_bucket_name
  internal_s3_bucket              = module.internal_s3.s3_bucket_name
  logging_account_id              = var.logging_account_id
  subscription_filter_destination = var.subscription_filter_destination
  filter_pattern                  = var.filter_pattern
  issuing_ca_list                 = var.issuing_ca_list
  lambda_role_arn                 = module.create_issuing_ca_iam.lambda_role_arn
  domain                          = var.hosted_zone_domain
  runtime                         = var.runtime
  public_crl                      = var.public_crl
  sns_topic_arn                   = module.sns_ca_notifications.sns_topic_arn
}

module "rsa_issuing_ca_crl_lambda" {
  # Lambda function to publish Issuing CA CRL signed by Issuing CA KMS private key
  source = "./modules/terraform-aws-ca-lambda"

  project                         = var.project
  env                             = var.env
  function_name                   = "issuing-ca-crl"
  description                     = "publish Issuing CA certificate revocation list signed by KMS private key"
  external_s3_bucket              = module.external_s3.s3_bucket_name
  internal_s3_bucket              = module.internal_s3.s3_bucket_name
  logging_account_id              = var.logging_account_id
  subscription_filter_destination = var.subscription_filter_destination
  filter_pattern                  = var.filter_pattern
  issuing_ca_list                 = var.issuing_ca_list
  issuing_crl_days                = var.issuing_crl_days
  issuing_crl_seconds             = var.issuing_crl_seconds
  lambda_role_arn                 = module.issuing_crl_iam.lambda_role_arn
  domain                          = var.hosted_zone_domain
  runtime                         = var.runtime
  public_crl                      = var.public_crl
  sns_topic_arn                   = module.sns_ca_notifications.sns_topic_arn
}