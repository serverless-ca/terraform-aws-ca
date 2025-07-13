locals {
  account_id = data.aws_caller_identity.current.account_id

  kms_arns_symmetric = distinct([
    for arn in [var.kms_arn_tls_keygen, var.kms_arn_resource] : arn if arn != ""
  ])
}