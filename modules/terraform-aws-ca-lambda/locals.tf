locals {
  file_name  = replace(var.function_name, "-", "_")
  public_crl = var.public_crl ? "enabled" : "disabled"
}