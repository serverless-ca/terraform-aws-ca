locals {
    template_name_prefix = contains(var.cert_info_files, "tls") ? "ca" : "ca-no-gitops"
}