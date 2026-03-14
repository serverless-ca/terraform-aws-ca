locals {
  file_name  = replace(var.function_name, "-", "_")
  public_crl = var.public_crl ? "enabled" : "disabled"

  ca_variables = {
    DOMAIN              = var.domain
    ENVIRONMENT_NAME    = var.env
    PROD_ENVIRONMENTS   = jsonencode(var.prod_envs)
    EXPIRY_REMINDERS    = jsonencode(var.expiry_reminders)
    EXTERNAL_S3_BUCKET  = var.external_s3_bucket
    INTERNAL_S3_BUCKET  = var.internal_s3_bucket
    ISSUING_CA_INFO     = jsonencode({ for k, v in var.issuing_ca_info : k => v if v != null })
    ISSUING_CRL_DAYS    = tostring(var.issuing_crl_days)
    ISSUING_CRL_SECONDS = tostring(var.issuing_crl_seconds)
    MAX_CERT_LIFETIME   = tostring(var.max_cert_lifetime)
    PROJECT             = var.project
    PUBLIC_CRL          = local.public_crl
    ROOT_CA_INFO        = jsonencode({ for k, v in var.root_ca_info : k => v if v != null })
    ROOT_CRL_DAYS       = tostring(var.root_crl_days)
    ROOT_CRL_SECONDS    = tostring(var.root_crl_seconds)
    SNS_TOPIC_ARN       = var.sns_topic_arn
  }

  slack_variables = {
    SLACK_SECRET_ARN    = var.slack_secret_arn
    SLACK_CHANNELS      = join(",", var.slack_channels)
    SLACK_BAD_EMOJI     = var.slack_bad_emoji
    SLACK_GOOD_EMOJI    = var.slack_good_emoji
    SLACK_WARNING_EMOJI = var.slack_warning_emoji
    SLACK_USERNAME      = var.slack_username
    PROJECT             = var.project
  }
}