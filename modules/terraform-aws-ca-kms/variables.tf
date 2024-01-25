variable "project" {}
variable "region" {}

variable "description" {
  description = "description of KSM key overrides default"
  default     = ""
}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "kms_policy" {
  description = "KMS policy to use"
  default     = "default"
}

variable "customer_master_key_spec" {
  description = "symmetric default or asymmetric algorithm"
  default     = "SYMMETRIC_DEFAULT"

  validation {
    condition = contains([
      "SYMMETRIC_DEFAULT",
      "RSA_2048",
      "RSA_3072",
      "RSA_4096",
      "HMAC_256",
      "ECC_NIST_P256",
      "ECC_NIST_P384",
      "ECC_NIST_P521",
      "ECC_SECG_P256K1",
    ], var.customer_master_key_spec)
    error_message = "Invalid customer_master_key_spec"
  }
}

variable "key_usage" {
  description = "intended use of the key"
  default     = "ENCRYPT_DECRYPT"

  validation {
    condition = contains([
      "ENCRYPT_DECRYPT",
      "SIGN_VERIFY",
      "GENERATE_VERIFY_MAC",
    ], var.key_usage)
    error_message = "Invalid key_usage"
  }
}
