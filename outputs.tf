output "cloudfront_domain_name" {
  value = var.public_crl ? module.ca_cloudfront[0].cloudfront_domain_name : null
}