locals {
  root_ca_info = {
    country              = "GB"
    locality             = "London"
    lifetime             = 7300
    organization         = "My Org"
    organizationalUnit   = "Security"
    commonName           = "My Org Root CA"
    pathLengthConstraint = 1
  }

  issuing_ca_list = {
    my-issuing = {
      country              = "GB"
      locality             = "London"
      lifetime             = 3650
      organization         = "My Org"
      organizationalUnit   = "Security"
      commonName           = "First Issuing CA"
      pathLengthConstraint = 0
    }
    my-second-issuing = {
      country              = "GB"
      locality             = "London"
      lifetime             = 3650
      organization         = "My Org"
      organizationalUnit   = "Security"
      commonName           = "Second Issuing CA"
      pathLengthConstraint = 0
    }
  }
}

