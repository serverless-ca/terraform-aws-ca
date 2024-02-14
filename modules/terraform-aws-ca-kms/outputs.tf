output "kms_arn" {
  value = aws_kms_key.encryption.arn
}

output "kms_alias_arn" {
  value = aws_kms_alias.encryption.arn
}

output "kms_alias_target_key_arn" {
  value = aws_kms_alias.encryption.target_key_arn
}
