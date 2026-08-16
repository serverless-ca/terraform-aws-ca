module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/ca/aws"
  # version = "1.0.0"

  bucket_prefix = "my-company"

  # distinct project name so this post-quantum CA can share an AWS account with a
  # classical CA deployment (e.g. rsa-public-crl) using the same environment name
  project = "pqc"
  env     = "prod"

  # public CRL and CA certificates are published to the rsa-public-crl deployment's
  # external bucket as pqc-prefixed files (e.g. pqc-issuing-ca.crl), served by that
  # deployment's existing CloudFront distribution at the same domain - no additional
  # CloudFront distribution, TLS certificate or DNS record is created
  external_s3_bucket_name = "my-company-serverless-ca-external-prod"
  hosted_zone_domain      = var.hosted_zone_domain

  issuing_ca_info = local.issuing_ca_info
  root_ca_info    = local.root_ca_info

  # post-quantum CA hierarchy (FIPS 204 / RFC 9881):
  # ML-DSA-65 root CA (NIST security category 3) signing an ML-DSA-44 issuing CA (category 2)
  root_ca_key_spec    = "ML_DSA_65"
  issuing_ca_key_spec = "ML_DSA_44"

  public_crl      = true
  cert_info_files = ["tls", "revoked", "revoked-root-ca"]
  slack_channels  = ["devsecops"]
  slack_token     = var.slack_token
  xray_enabled    = false

  # allowlist a private-enterprise OID so the custom extensions integration test runs
  # against this deployment, as it does against examples/rsa-public-crl
  custom_extension_allowlist = ["1.3.6.1.4.1.55555.1.1"]

  custom_sns_topic_display_name = "My Company CA Notifications PQC"
  dynamodb_deletion_protection  = false
}
