resource "aws_secretsmanager_secret" "secret" {
  name                    = "${lower(var.project)}-${lower(var.purpose)}-${lower(var.env)}"
  description             = var.description
  kms_key_id              = var.kms_key_id == "" ? null : var.kms_key_id
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "value_not_managed_by_terraform" {
  count         = var.ignore_value_changes ? 1 : 0
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = var.value

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_version" "value_managed_by_terraform" {
  count         = var.ignore_value_changes ? 0 : 1
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = var.value
}
