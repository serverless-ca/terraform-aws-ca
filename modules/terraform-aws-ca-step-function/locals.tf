locals {
  has_gitops           = contains(var.cert_info_files, "tls")
  has_expiry           = length(var.expiry_reminders) > 0
  template_name_prefix = local.has_gitops && local.has_expiry ? "ca-expiry" : local.has_gitops ? "ca" : "ca-no-gitops"
}