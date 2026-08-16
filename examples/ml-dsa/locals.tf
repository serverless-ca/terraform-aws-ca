locals {
  issuing_ca_info = {
    country              = "GB"
    locality             = "London"
    lifetime             = 3650
    organization         = "My Company"
    organizationalUnit   = "Security Operations"
    commonName           = "My Company ML-DSA Issuing CA"
    pathLengthConstraint = 0
  }

  root_ca_info = {
    country              = "GB"
    locality             = "London"
    lifetime             = 7300
    organization         = "My Company"
    organizationalUnit   = "Security Operations"
    commonName           = "My Company ML-DSA Root CA"
    pathLengthConstraint = 1
  }
}
