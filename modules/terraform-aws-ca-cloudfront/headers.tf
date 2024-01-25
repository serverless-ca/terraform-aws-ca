resource "aws_cloudfront_response_headers_policy" "policy" {

  name = "${local.project_slug}-response-headers-policy-${var.environment}"

  cors_config {
    access_control_allow_credentials = false

    access_control_allow_methods {
      items = [
        "GET",
        "HEAD"
      ]
    }

    access_control_allow_headers {
      items = ["*"]
    }

    access_control_allow_origins {
      items = [
        "ajax.googleapis.com",
        "fonts.gstatic.com",
        "maps.gstatic.com",
        "maps.google.com",
        "maps.googleapis.com"
      ]
    }

    access_control_expose_headers {
      items = ["*"]
    }

    access_control_max_age_sec = 86400
    origin_override            = true
  }

  security_headers_config {

    content_type_options {
      override = true
    }

    frame_options {
      override     = true
      frame_option = "SAMEORIGIN"
    }

    referrer_policy {
      override        = true
      referrer_policy = "strict-origin-when-cross-origin"
    }

    strict_transport_security {
      override                   = true
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
    }

    xss_protection {
      override   = true
      mode_block = true
      protection = true
    }
  }

  custom_headers_config {
    items {
      header   = "permissions-policy"
      override = true
      value    = "accelerometer=(none), ambient-light-sensor=(none), autoplay=(none), camera=(none), encrypted-media=(none), fullscreen=(none), geolocation=(none), gyroscope=(none), magnetometer=(none), microphone=(none), midi=(none), payment=(none), picture-in-picture=(none), speaker=(none), usb=(none), vibrate=(none), vr=(none)"
    }
  }
}