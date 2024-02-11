module "certificate_authority" {
  source = "../../"
  # source  = "serverless-ca/terraform-aws-ca"
  # version = "0.1.0"

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # required even if CloudFront not used
  }
}
