locals {
  runtime = coalesce(var.runtime, format("python%s", regex("^\\d+\\.\\d+", file("${path.module}/python-version"))))

  create_root_ca_lambda_name        = "create-root-ca"
  create_rsa_issuing_ca_lambda_name = "create-issuing-ca"
  rsa_root_ca_crl_lambda_name       = "root-ca-crl"
  rsa_issuing_ca_crl_lambda_name    = "issuing-ca-crl"
  rsa_tls_cert_lambda_name          = "tls-cert"
  expiry_lambda_name                = "expiry"
  notify_lambda_name                = "notify"
}
