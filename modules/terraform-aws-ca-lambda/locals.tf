locals {
  file_name         = replace(var.function_name, "-", "_")
  client_keys_in_db = var.allow_client_keys_in_db ? "enabled" : "disabled"
  public_crl        = var.public_crl ? "enabled" : "disabled"
}