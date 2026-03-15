locals {
  account_id           = data.aws_caller_identity.current.account_id
  region               = data.aws_region.current.id
  lambda_function_name = var.lambda_function_name != "" ? var.lambda_function_name : var.function_name

  kms_arns_symmetric = distinct([
    for arn in [var.kms_arn_tls_keygen, var.kms_arn_resource] : arn if arn != ""
  ])
}