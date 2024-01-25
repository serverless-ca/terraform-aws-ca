locals {
  domain_name  = var.domain_prefix == "" ? var.base_domain : "${var.domain_prefix}.${var.base_domain}"
  domain_ref   = replace(local.domain_name, ".", "-")
  project_slug = lower(replace(var.project, " ", "-"))
}