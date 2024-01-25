resource "aws_cloudfront_origin_request_policy" "policy" {

  name = "${local.project_slug}-origin-request-policy-${var.environment}"

  cookies_config {
    cookie_behavior = "whitelist"
    cookies {
      items = ["catAccCookies"]
    }
  }
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "sec-fetch-mode",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-fetch-site",
        "Accept",
        "sec-ch-ua-platform",
        "Referer",
        "User-Agent",
        "Accept-Language",
        "sec-fetch-dest"
      ]
    }
  }
  query_strings_config {
    query_string_behavior = "all"
  }
}