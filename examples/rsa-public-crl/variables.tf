variable "hosted_zone_domain" {
  description = "Hosted Zone Domain"
  default     = "ca.example.com" # Change to subdomain hosted zone for CRL publication within same AWS account
}

variable "allow_client_keys_in_db" {
  description = "Do not change the default setting - feature will be deprecated in a future release"
  default     = false
}