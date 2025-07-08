locals {
  issuing_ca_info = {
    country              = "GB"
    locality             = "London"
    lifetime             = 3650
    organization         = "My Company"
    organizationalUnit   = "Security Operations"
    commonName           = "My Company Issuing CA"
    pathLengthConstraint = 0
  }

  root_ca_info = {
    country              = "GB"
    locality             = "London"
    lifetime             = 7300
    organization         = "My Company"
    organizationalUnit   = "Security Operations"
    commonName           = "My Company Root CA"
    pathLengthConstraint = 1
  }

  additional_dynamodb_tags = {
    "BackupPolicy" = "ca-prod"
  }

  additional_s3_tags = {
    "BackupPolicy" = "ca-prod"
  }
}
