variable "hosted_zone_domain" {
  description = "Hosted Zone Domain"
  default     = "ca.example.com" # Change to subdomain hosted zone for CRL publication within same AWS account
}

variable "slack_token" {
  type        = string
  description = "Slack App OAuth token"
  default     = ""
}
