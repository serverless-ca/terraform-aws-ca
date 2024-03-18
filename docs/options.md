# Configuration Options

The serverless CA is highly configurable by adjusting values of Terraform variables in [variables.tf](https://github.com/serverless-ca/terraform-aws-ca/blob/main/variables.tf). Principal configuration options:


## Revocation and GitOps
By default, certificate revocation and GitOps are disabled. If you followed the [Getting Started](./getting-started.md) guide you'll already have enabled GitOps:
* add a subdirectory to your repository with the same name as the value of the Terraform variable `env`, e.g. `dev`, `prd`
add files and subdirectory following [the rsa-public-crl example](https://github.com/serverless-ca/terraform-aws-ca/blob/main/examples/rsa-public-crl/README.md)
* change the value of Terraform variable `cert_info_files` to  `["tls", "revoked", "revoked-root-ca"]`
* apply Terraform
* you can now revoke a certificate as described in [Revocation](revocation.md)

## Public CRL and CA certs

See details in [Revocation](revocation.md) and [CA Cert Locations](locations.md).

*Default setting: not enabled*

## CA key algorithms

The following algorithms can be selected via Terraform [variables](https://github.com/serverless-ca/terraform-aws-ca/blob/main/variables.tf):
`RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521`

*Default setting: `ECC_NIST_P384` (Root CA), `ECC_NIST_P256` (Issuing CA)*

## CloudWatch log subscription filters

CloudWatch log subscription filters can be used to send log events to a central S3 log bucket, from which they can be forwarded to a SIEM.

*Default setting: not enabled*

## CRL publication frequency
To avoid certificate validation errors, it's essential that the CRL publication interval is less than, or equal to, the CRL lifetime. This ensures there is always a valid CRL at any time.
* CRLs are published once every 24 hours by default
* CRLs can be published manually by executing the CA Step Function
* Issuing CA and Root CA CRLs are publised at the same time
* Publication frequency can be changed using the Terraform variable `schedule_expression`
* Generally there should be no need to change this value from the default

*Default setting: once per day at 08:15 a.m.*

## CRL lifetime
To avoid certificate validation errors, it's essential that the CRL lifetime is equal to, or greater than, the publication interval. This ensures there is always a valid CRL at any time.
* Issuing CA CRL lifetime can be adjusted using the Terraform variables `issuing_crl_days` and `issuing_crl_seconds`
* `issuing_crl_days` should normally be identical to the interval configured in `schedule_expression`
* `issuing_crl_seconds` is an additional time period used as an overlap in case of clock skew
* Similarly, Root CA CRL lifetime can be adjusted using the Terraform variables `root_crl_days` and `root_crl_seconds`
 * Generally there should be no need to change these values from their defaults

 *Default setting (Issuing and Root CA CRLs): 1 day with a 600 second overlap period*