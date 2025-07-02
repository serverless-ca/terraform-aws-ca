resource "aws_dynamodb_table" "ca" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "CommonName"
  range_key    = "SerialNumber"

  attribute {
    name = "CommonName"
    type = "S"
  }

  attribute {
    name = "SerialNumber"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_arn_resource
  }

  tags = local.tags
}
