resource "aws_iam_role" "lambda" {
  name = "${var.project}-${var.function_name}-${var.env}"
  assume_role_policy = templatefile("${path.module}/templates/${var.assume_role_policy}_role.json.tpl", {
    aws_principals = var.aws_principals
    project        = var.project
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${var.project}-${var.function_name}-${var.env}"
  role = aws_iam_role.lambda.id
  policy = templatefile("${path.module}/templates/${var.policy}_policy.json.tpl", {
    kms_arn_issuing_ca     = var.kms_arn_issuing_ca,
    kms_arn_root_ca        = var.kms_arn_root_ca,
    kms_arn_tls_keygen     = var.kms_arn_tls_keygen,
    kms_arn_resource       = var.kms_arn_resource,
    ddb_table_arn          = var.ddb_table_arn,
    external_s3_bucket_arn = var.external_s3_bucket_arn,
    internal_s3_bucket_arn = var.internal_s3_bucket_arn
    sns_topic_arn          = var.sns_topic_arn
  })
}

resource "aws_iam_role_policy_attachment" "xray" {
  count      = var.xray_enabled ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = var.xray_daemon_policy_arn
}
