module "certificate_authority" {
  source  = "../../"
  # source  = "serverless-ca/ca/aws"
  # version = "1.6.2"

  issuing_ca_list     = local.issuing_ca_list
  cert_info_files     = concat(["revoked-root-ca"], [for name, _ in local.issuing_ca_list: "${name}-revoked"])
  root_ca_info        = local.root_ca_info

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # required even if CloudFront not used
  }
}
