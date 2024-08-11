locals {
  sns_topic_display_name = coalesce(var.custom_sns_topic_name, title(replace("${var.project}-${var.function}-${var.env}", "-", " ")))
  sns_topic_name         = coalesce(var.custom_sns_topic_name, "${var.project}-${var.function}-${var.env}")

  tags = merge(var.tags, {
    Terraform = "true"
    Name      = local.sns_topic_name,
  })
}
