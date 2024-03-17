# Configuration Options
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Automation](automation.md) | [Security](security.md) | [FAQ](faq.md) |  

The serverless CA is highly configurable by adjusting values of Terraform variables in [variables.tf](../variables.tf). Principal configuration options:


## Revocation and GitOps
By default, certificate revocation and GitOps are disabled. If you followed the [Getting Started](./getting-started.md) guide you'll already have enabled GitOps:
* add a subdirectory to your repository with the same name as the value of the Terraform variable `env`, e.g. `dev`, `prd`
add files and subdirectory following [the rsa-public-crl example](../examples/rsa-public-crl/README.md)
* change the value of Terraform variable `cert_info_files` to  `["tls", "revoked", "revoked-root-ca"]`
* apply Terraform
* you can now revoke a certificate as described in [Revocation](revocation.md)

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