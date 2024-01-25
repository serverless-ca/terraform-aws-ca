resource "aws_cloudfront_cache_policy" "policy" {

  name        = "${local.domain_ref}-cache-policy"
  comment     = "Cache policy for ${local.domain_name}"
  default_ttl = 10
  max_ttl     = 10
  min_ttl     = 1

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }

    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}