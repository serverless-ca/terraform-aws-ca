# CRL and CA Cert Locations
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Automation](automation.md) | [Security](security.md) | [FAQ](faq.md) |  

In all cases, CRLs and CA certificates are published to the `external` S3 bucket, which is not directly accessible from the public Internet.

If you choose to publish CRLs and CA certificates:
* Domain name is that of the hosted zone in your CA AWS account
* CA certificates are made available via CloudFront
* Authority Information Access (AIA) extension added to issued certificates with CA certificate location
* CRL Distribution Point (CDP) extension added to issued certificates with CRL location
* CRLs are published to CloudFront
* For details on how to revoke a certificate, see [CRL](crl.md)
* File names are constructed using the `project_name` and `environment` Terraform variables

See [CRL](crl.md) for details of how to enable public CRLs and CA certs.

## Example locations
* locations below for an [example deployment](../examples/rsa-public-crl) in the [terraform-aws-ca](https://github.com/q-solution/terraform-aws-ca) repository.
* infrastructure deployed by a [GitHub Actions test workflow](../.github/workflows/rsa_public_crl.yml) in the [terraform-aws-ca](https://github.com/q-solution/terraform-aws-ca) repository.
* `project_name` is `serverless` and `environment` is either `dev` (not deployed, for illustration only) or `prod` (deployed)
* environment suffix automatically omitted for `prod` or `prd` environment

## CRL Distribution Point (CDP)

| environment | hosted zone domain |                                       CDP - Root CA                                        |                                         CDP - Issuing CA                                         |
|-------------|:------------------:|:------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------:|
| dev *       | dev.ca.celidor.io  |                    http://dev.ca.celidor.io/serverless-root-ca-dev.crl                     |                      http://dev.ca.celidor.io/serverless-issuing-ca-dev.crl                      |
| prod        |   ca.celidor.io    | [http://ca.celidor.io/serverless-root-ca.crl](http://ca.celidor.io/serverless-root-ca.crl) | [http://ca.celidor.io/serverless-issuing-ca.crl](http://ca.celidor.io/serverless-issuing-ca.crl) |

* `dev` environment not deployed, for illustration only

## Authority Information Access (AIA)

| environment | hosted zone domain |                                       AIA - Root CA                                        |                                       AIA - Issuing CA                                        |
|-------------|:------------------:|:------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------:|
| dev *       | dev.ca.celidor.io  |                    http://dev.ca.celidor.io/serverless-root-ca-dev.crt                     |                    http://dev.ca.celidor.io/serverless-issuing-ca-dev.crt                     |
| prod        |   ca.celidor.io    | [http://ca.celidor.io/serverless-root-ca.crt](http://ca.celidor.io/serverless-root-ca.crt) | [http://ca.celidor.io/serverless-issuing-ca.crt](http://ca.celidor.io/serverless-root-ca.crt) |

* `dev` environment not deployed, for illustration only

## CA Bundle (for TrustStore)

| environment | hosted zone domain |                                          CA Bundle                                           |
|-------------|:------------------:|:--------------------------------------------------------------------------------------------:|
| dev *       | dev.ca.celidor.io  |                      http://dev.ca.celidor.io/serverless-ca-bundle-dev.pem                       |
| prod        |   ca.celidor.io    | [http://ca.celidor.io/serverless-ca-bundle.pem](http://ca.celidor.io/serverless-root-ca.crt) |

* `dev` environment not deployed, for illustration only