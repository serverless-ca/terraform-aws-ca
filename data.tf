data "aws_s3_bucket" "external" {
  # existing external bucket shared with another CA deployment in this account
  count  = var.external_s3_bucket_name == "" ? 0 : 1
  bucket = var.external_s3_bucket_name
}

data "aws_secretsmanager_secret" "shared_slack" {
  # Slack OAuth token secret owned by another CA deployment in the same AWS account and region
  count = length(var.slack_channels) > 0 && var.existing_slack_secret_name != "" ? 1 : 0

  name = var.existing_slack_secret_name
}
