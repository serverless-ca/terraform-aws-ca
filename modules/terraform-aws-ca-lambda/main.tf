resource "null_resource" "install_python_dependencies" {
  triggers = {
    # detect changes to Lambda code
    source_archive_checksum = data.archive_file.lambda_source.output_base64sha256

    # detect changes to files in utils directory
    dir_sha1 = sha1(join("", [for f in fileset("${path.module}/utils", "**") : filesha1("${path.module}/utils/${f}")]))

    # static value (true) if present, variable value (timestamp()) when not present. (so the 'false' state isn't static and forces a build by change of state whenever so. a static false value doesn't force change of state.)
    build_already_present = fileexists("${path.module}/build/${local.file_name}/__init__.py") ? true : timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
      chmod +x ${path.module}/scripts/lambda-build/create-package.sh
      ./${path.module}/scripts/lambda-build/create-package.sh
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

data "archive_file" "lambda_source" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_code/${local.file_name}"
  output_path = "${path.module}/archive/${local.file_name}.src.zip"
}

data "archive_file" "lambda_zip" {
  depends_on  = [null_resource.install_python_dependencies]
  type        = "zip"
  source_dir  = "${path.module}/build/${local.file_name}"
  output_path = "${path.module}/archive/${local.file_name}.zip"
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

  environment {
    variables = {
      DOMAIN             = var.domain
      ENVIRONMENT_NAME   = var.env
      EXTERNAL_S3_BUCKET = var.external_s3_bucket
      INTERNAL_S3_BUCKET = var.internal_s3_bucket
      ISSUING_CA_INFO    = jsonencode(var.issuing_ca_info)
      PROJECT            = var.project
      PUBLIC_CRL         = local.public_crl
      ROOT_CA_INFO       = jsonencode(var.root_ca_info)
    }
  }

  tracing_config {
    mode = "Active"
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
