output "cloudfront_origin_access_identity_arn" {
  value = aws_cloudfront_origin_access_identity.website.iam_arn
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.website.domain_name
}

output "cloudfront_hosted_zone_id" {
  value = aws_cloudfront_distribution.website.hosted_zone_id
}

