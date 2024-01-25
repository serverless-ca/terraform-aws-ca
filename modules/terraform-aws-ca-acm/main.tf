resource "aws_acm_certificate" "certificate" {
  domain_name               = var.domain_name
  validation_method         = var.validation_method
  subject_alternative_names = [var.domain_name]

  options {
    certificate_transparency_logging_preference = var.certificate_transparency
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.certificate.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 86400
  type            = each.value.type
  zone_id         = var.zone_id
}

resource "aws_acm_certificate_validation" "validation" {
  certificate_arn         = aws_acm_certificate.certificate.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}
