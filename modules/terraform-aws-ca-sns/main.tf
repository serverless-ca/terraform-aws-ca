resource "aws_sns_topic" "sns_topic" {
  name   = local.sns_topic_name
  policy = coalesce(var.sns_policy, templatefile("${path.module}/templates/${var.sns_policy_template}.json", { region = data.aws_region.current.id, account_id = data.aws_caller_identity.current.account_id, sns_topic_name = local.sns_topic_name }))

  tags = merge(
    var.tags,
    tomap(
      { "Name" = local.sns_topic_name }
    )
  )
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "email_subscriptions" {
  for_each             = toset(var.email_subscriptions)
  endpoint             = each.key
  protocol             = "email"
  topic_arn            = aws_sns_topic.sns_topic.arn
  raw_message_delivery = false
}

resource "aws_sns_topic_subscription" "lambda_subscriptions" {
  for_each             = var.lambda_subscriptions
  endpoint             = each.value
  protocol             = "lambda"
  topic_arn            = aws_sns_topic.sns_topic.arn
  raw_message_delivery = false
}

resource "aws_sns_topic_subscription" "sqs_subscriptions" {
  for_each             = var.sqs_subscriptions
  endpoint             = each.value
  protocol             = "sqs"
  topic_arn            = aws_sns_topic.sns_topic.arn
  raw_message_delivery = true
}
