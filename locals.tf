locals {
  runtime = coalesce(var.runtime, format("python%s", regex("^\\d+\\.\\d+", file("${path.module}/python-version"))))

  # external bucket for CRL / CA certificate publication: either created by this
  # deployment or an existing bucket shared with another CA deployment in the account
  external_s3_bucket_name        = var.external_s3_bucket_name == "" ? module.external_s3[0].s3_bucket_name : data.aws_s3_bucket.external[0].bucket
  external_s3_bucket_arn         = var.external_s3_bucket_name == "" ? module.external_s3[0].s3_bucket_arn : data.aws_s3_bucket.external[0].arn
  external_s3_bucket_domain_name = var.external_s3_bucket_name == "" ? module.external_s3[0].s3_bucket_domain_name : data.aws_s3_bucket.external[0].bucket_domain_name

  create_root_ca_function_name    = "create-root-ca"
  create_issuing_ca_function_name = "create-issuing-ca"
  root_ca_crl_function_name       = "root-ca-crl"
  issuing_ca_crl_function_name    = "issuing-ca-crl"
  tls_cert_function_name          = "tls-cert"
  expiry_function_name            = "expiry"
  notify_function_name            = "notify"
}
