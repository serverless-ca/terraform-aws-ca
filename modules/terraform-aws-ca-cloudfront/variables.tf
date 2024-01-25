variable "project" {
  description = "Project name"
}

variable "bucket_name" {
  description = "Name of origin S3 bucket"
}

variable "bucket_regional_domain_name" {
  description = "Regional domain name of origin S3 bucket"
}

variable "certificate_arn" {
  description = "Certificate ARN"
}

variable "base_domain" {
  description = "Base domain, e.g. example.com"
}

variable "domain_prefix" {
  description = "Domain prefix, e.g. www"
  default     = ""
}

variable "environment" {
  description = "Abbreviation for environment, e.g. dev, prd"
}

variable "zone_id" {
  description = "Route53 hosted zone ID"
}

variable "error_page" {
  description = "Path to custom 404 error page"
  default     = "/page-not-found.html"
}
