data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "public" {
  name         = "${var.hosted_zone_domain}."
  private_zone = false
}
