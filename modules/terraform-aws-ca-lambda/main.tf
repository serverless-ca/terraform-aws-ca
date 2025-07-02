resource "null_resource" "install_python_dependencies" {
  triggers = {
    # detect changes to Lambda code
    lambda_code_sha256 = sha256(join("", [for f in sort(tolist(fileset("${path.module}/lambda_code/${local.file_name}", "**"))) : filesha256("${path.module}/lambda_code/${local.file_name}/${f}")]))

    # detect changes to files in utils directory
    utils_sha256 = sha256(join("", [for f in sort(tolist(fileset("${path.module}/utils", "**"))) : filesha256("${path.module}/utils/${f}")]))

    # static value (true) if present, variable value (timestamp()) when not present. (so the 'false' state isn't static and forces a build by change of state whenever so. a static false value doesn't force change of state.)
    build_already_present = fileexists("${path.module}/build/${local.file_name}/__init__.py") ? true : timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      chmod +x ${path.module}/scripts/lambda-build/create-package.sh
      ${path.module}/scripts/lambda-build/create-package.sh
    EOT

    environment = {
      source_code_path = "${path.module}/lambda_code"
      function_name    = local.file_name
      runtime          = var.runtime
      path_cwd         = path.module
      platform         = var.platform
    }
  }
}

data "archive_file" "lambda_zip" {
  depends_on  = [null_resource.install_python_dependencies]
  type        = "zip"
  source_dir  = "${path.module}/build/${local.file_name}"
  output_path = "${path.module}/build/${local.file_name}.zip"
}

resource "aws_lambda_function" "lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.project}-${var.function_name}-${var.env}"
  description      = "${var.project} ${var.description}"
  role             = var.lambda_role_arn
  handler          = "${local.file_name}.lambda_handler"
  runtime          = var.runtime
  memory_size      = var.memory_size
  timeout          = var.timeout
  publish          = true
  tags             = var.tags

  environment {
    variables = {
      DOMAIN              = var.domain
      ENVIRONMENT_NAME    = var.env
      PROD_ENVIRONMENTS   = jsonencode(var.prod_envs)
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
  }

  tracing_config {
    mode = var.xray_enabled ? "Active" : "PassThrough"
  }

  depends_on = [data.archive_file.lambda_zip]
}

resource "aws_lambda_alias" "lambda" {
  name             = "${var.project}-${var.function_name}-${var.env}"
  description      = "Alias for ${var.project}-${var.function_name}-${var.env}"
  function_name    = aws_lambda_function.lambda.function_name
  function_version = "$LATEST"
}

resource "aws_lambda_permission" "lambda_invoke" {
  for_each = toset(var.allowed_invocation_principals)

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = each.value
}
