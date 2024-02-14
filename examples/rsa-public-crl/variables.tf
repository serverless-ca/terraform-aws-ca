variable "hosted_zone_domain" {
  description = "Hosted Zone Domain"
  default     = "ca.example.com" # Change to subdomain hosted zone for CRL publication within same AWS account
}

variable "cert_info_files" {
  description = "List of file names to be uploaded to internal S3 bucket for processing"
  default     = ["tls", "revoked", "revoked-root-ca"]
}
