resource "aws_cloudwatch_log_group" "log_group_for_sfn" {
  #checkov:skip=CKV_AWS_158:Agreed to not require CMK's KMS for cloudwatch
  name              = "/aws/vendedlogs/states/${var.project}-${var.purpose}-${var.env}"
  retention_in_days = var.retention_in_days
}

resource "aws_sfn_state_machine" "state_machine" {
  definition = templatefile("${path.module}/templates/${local.template_name_prefix}.json.tpl", {
    account_id         = data.aws_caller_identity.current.account_id,
    project            = var.project,
    env                = var.env,
    region             = data.aws_region.current.region
    internal_s3_bucket = var.internal_s3_bucket
  })
  name     = "${var.project}-${var.purpose}-${var.env}"
  role_arn = var.role_arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.log_group_for_sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }
}
