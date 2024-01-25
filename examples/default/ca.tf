module "certificate_authority" {
  source = "../../"

  providers = {
    aws           = aws
    aws.us-east-1 = aws.us-east-1 # required even if CloudFront not used
  }
}
