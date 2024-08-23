resource "aws_kms_key" "encryption" {
  description             = var.description == "" ? local.key_description : var.description
  deletion_window_in_days = 7
  enable_key_rotation     = var.enable_key_rotation
  policy = templatefile("${path.module}/templates/${var.kms_policy}.json.tpl", {
    account_id = data.aws_caller_identity.current.account_id,
    region     = data.aws_region.current.name
  })
  customer_master_key_spec = var.customer_master_key_spec
  key_usage                = var.key_usage
}

resource "aws_kms_alias" "encryption" {
  name          = contains(["prd", "prod"], var.env) ? "alias/${var.project}" : "alias/${var.project}-${var.env}"
  target_key_id = aws_kms_key.encryption.key_id
}
