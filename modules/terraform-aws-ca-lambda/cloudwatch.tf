resource "aws_cloudwatch_log_group" "function_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.lambda.function_name}"
  retention_in_days = var.retention_in_days
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_cloudwatch_log_subscription_filter" "logs_to_s3_sentinel" {
  count = var.subscription_filter_destination == "" || var.logging_account_id == "" ? 0 : 1

  name            = "${lower(replace(aws_lambda_function.lambda.function_name, " ", "-"))}-logs-to-s3-sentinel-${var.env}"
  log_group_name  = aws_cloudwatch_log_group.function_log_group.name
  filter_pattern  = var.filter_pattern
  destination_arn = "arn:aws:logs:${data.aws_region.current.region}:${var.logging_account_id}:destination:${var.subscription_filter_destination}"
}
