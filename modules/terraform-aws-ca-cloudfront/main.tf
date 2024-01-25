resource "aws_cloudfront_origin_access_identity" "website" {

  comment = "Allows access to ${var.bucket_name} S3 bucket"
}

resource "aws_cloudfront_distribution" "website" {

  origin {
    domain_name = var.bucket_regional_domain_name
    origin_id   = "${local.domain_ref}-${var.environment}"
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.website.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Static web site for ${local.domain_name}"
  default_root_object = "index.html"

  aliases = [var.domain_prefix == "" ? var.base_domain : "${var.domain_prefix}.${var.base_domain}"]

  default_cache_behavior {
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = "${local.domain_ref}-${var.environment}"
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.policy.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.policy.id
    viewer_protocol_policy     = "allow-all"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["CN", "IR", "KP", "RU"]
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }

  custom_error_response {
    error_caching_min_ttl = 10
    error_code            = 403
    response_code         = 404
    response_page_path    = var.error_page
  }

  custom_error_response {
    error_caching_min_ttl = 10
    error_code            = 404
    response_code         = 404
    response_page_path    = var.error_page
  }
}

resource "aws_route53_record" "cloudfront" {
  count   = var.domain_prefix == "" ? 0 : 1
  zone_id = var.zone_id
  name    = "${var.domain_prefix}.${var.base_domain}"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_cloudfront_distribution.website.domain_name]
}

resource "aws_route53_record" "cloudfront-apex" {
  count   = var.domain_prefix == "" ? 1 : 0
  zone_id = var.zone_id
  name    = var.base_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.website.domain_name
    zone_id                = aws_cloudfront_distribution.website.hosted_zone_id
    evaluate_target_health = false
  }
}