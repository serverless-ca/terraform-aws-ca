locals {
  algorithm = startswith(var.customer_master_key_spec, "RSA_") ? "RSA" : startswith(var.customer_master_key_spec, "ML_DSA_") ? "ML-DSA" : "ECDSA"
  ca_type   = contains(split("-", var.project), "root") ? "Root CA" : "Issuing CA"

  asymmetric_key_description = "${var.project}-${var.env} ${local.algorithm} ${local.ca_type} key pair"
  symmetric_key_description  = "Encryption of ${var.project}-${var.env} resources"
  key_description            = var.customer_master_key_spec == "SYMMETRIC_DEFAULT" ? local.symmetric_key_description : local.asymmetric_key_description
}