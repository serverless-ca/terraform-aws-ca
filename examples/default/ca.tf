module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/ca/aws"
  # version = "1.0.0"

  # cert_info_files     = ["tls", "revoked", "revoked-root-ca"]
  # issuing_ca_info     = local.issuing_ca_info
  # root_ca_info        = local.root_ca_info

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # required even if CloudFront not used
  }
}
