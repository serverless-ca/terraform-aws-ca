# Configuration Options
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Security](security.md) | [FAQ](faq.md) |  

The serverless CA is highly configurable by adjusting values of Terraform variables in [variables.tf](../variables.tf). Principal configuration options:

## Public CRL and CA certs

See details in [CRL](revocation.md) and [CA Cert Locations](locations.md).

*Default setting: not enabled*

## CA key algorithms

The following algorithms can be selected via Terraform [variables](../variables.tf):
`RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521`

*Default setting: `ECC_NIST_P384` (Root CA), `ECC_NIST_P256` (Issuing CA)*

## CloudWatch log subscription filters

CloudWatch log subscription filters can be used to send log events to a central S3 log bucket, from which they can be forwarded to a SIEM.

*Default setting: not enabled*