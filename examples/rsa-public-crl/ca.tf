module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/ca/aws"
  # version = "1.0.0"

  bucket_prefix       = "my-company"
  env                 = "prod"
  hosted_zone_domain  = var.hosted_zone_domain
  hosted_zone_id      = data.aws_route53_zone.public.zone_id
  issuing_ca_info     = local.issuing_ca_info
  root_ca_info        = local.root_ca_info
  issuing_ca_key_spec = "RSA_4096"
  root_ca_key_spec    = "RSA_4096"
  public_crl          = true
  cert_info_files     = ["tls", "revoked", "revoked-root-ca"]
  kms_key_alias       = "custom-kms-encryption-key"
  slack_channels      = ["devsecops"]
  slack_token         = var.slack_token
  xray_enabled        = false

  # Demonstrates the custom X.509 extensions feature: allowlist a private-enterprise OID
  # (under a placeholder PEN) that callers may then embed via the 'extensions' request
  # field. Also exercised by the integration tests in tests/test_issued_certs.py.
  custom_extension_allowlist = ["1.3.6.1.4.1.55555.1.1"]

  additional_dynamodb_tags      = local.additional_dynamodb_tags
  additional_s3_tags            = local.additional_s3_tags
  custom_sns_topic_display_name = "My Company CA Notifications Production"
  dynamodb_deletion_protection  = true
}
