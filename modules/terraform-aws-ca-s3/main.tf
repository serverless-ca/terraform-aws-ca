resource "aws_s3_bucket" "bucket" {
  #checkov:skip=CKV_AWS_144: region replication not required
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  tags = local.tags
}

resource "aws_s3_bucket_versioning" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  versioning_configuration {
    status = var.versioning
  }
}

resource "aws_s3_bucket_logging" "bucket" {
  count = var.access_logs ? 1 : 0

  bucket = aws_s3_bucket.bucket.id

  target_bucket = var.log_bucket
  target_prefix = "${local.bucket_name}/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kms" {
  count = var.server_side_encryption && var.sse_algorithm == "aws:kms" ? 1 : 0

  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_encryption_key_arn != "" ? var.kms_encryption_key_arn : local.kms_key_alias_arn
      sse_algorithm     = var.sse_algorithm
    }
    bucket_key_enabled = var.bucket_key_enabled
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3" {
  count = var.server_side_encryption && var.sse_algorithm == "AES256" ? 1 : 0

  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.sse_algorithm
    }
  }
}

resource "aws_s3_bucket_policy" "bucket" {
  bucket = aws_s3_bucket.bucket.id
  policy = templatefile("${path.module}/templates/${local.bucket_policy}.json.tpl", {
    bucket_name        = aws_s3_bucket.bucket.id,
    account_id         = data.aws_caller_identity.current.account_id,
    region             = data.aws_region.current.name,
    oai_arn            = var.oai_arn,
    app_aws_principals = var.app_aws_principals
  })
  depends_on = [aws_s3_bucket_public_access_block.bucket]
}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    object_ownership = var.object_ownership
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle" {
  count = var.lifecycle_policy ? 1 : 0

  bucket = aws_s3_bucket.bucket.id

  rule {
    id = "StandardRotation"

    transition {
      days          = var.ia_transition
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.glacier_transition
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = var.noncurrent_transition
      storage_class   = "GLACIER"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = var.abort_uploads
    }

    status = "Enabled"
  }
}
