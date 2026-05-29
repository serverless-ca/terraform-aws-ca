locals {
  runtime = coalesce(var.runtime, format("python%s", regex("^\\d+\\.\\d+", file("${path.module}/python-version"))))

  create_root_ca_function_name    = "create-root-ca"
  create_issuing_ca_function_name = "create-issuing-ca"
  root_ca_crl_function_name       = "root-ca-crl"
  issuing_ca_crl_function_name    = "issuing-ca-crl"
  tls_cert_function_name          = "tls-cert"
  expiry_function_name            = "expiry"
  notify_function_name            = "notify"
}
