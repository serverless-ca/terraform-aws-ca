module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/terraform-aws-ca"
  # version = "1.0.0"

  bucket_prefix       = "my-company"
  env                 = "prod"
  hosted_zone_domain  = var.hosted_zone_domain
  hosted_zone_id      = data.aws_route53_zone.public.zone_id
  issuing_ca_info     = local.issuing_ca_info
  root_ca_info        = local.root_ca_info
  issuing_ca_key_spec = "RSA_4096"
  issuing_crl_days    = 2 # temporary test
  root_ca_key_spec    = "RSA_4096"
  public_crl          = true
  cert_info_files     = ["tls", "revoked", "revoked-root-ca"]

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # certificates for CloudFront must be in this region
  }
}
