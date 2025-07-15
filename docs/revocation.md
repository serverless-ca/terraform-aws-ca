# Certificate Revocation

![Certificate Revocation List](assets/images/crl.png?raw=true)

* Certificates can be revoked using a Certificate Revocation List (CRL)
* Online Certificate Status Protocol (OCSP) is not supported

How-to guide: [Revoking access to IAM Roles Anywhere using open-source private CA](how-to-guides/crl.md)

## CRL publication
CRLs are published to `external` S3 bucket, not directly accessible from public Internet

To publish publicly, set `public_crl` to `true` and provide `hosted_zone_id` and `hosted_zone_name` in [Terraform variables](https://github.com/serverless-ca/terraform-aws-ca/blob/main/variables.tf).

Applying Terraform will result in:

* CRLs published to a public URL via CloudFront
* CA certificates published to a public URL via CloudFront
* CRL Distribution Point (CDP) extension added to certificates
* Authority Information Access (AIA) extension added to certificates

## CRL file formats
CRLs are published as:
* DER file format with `.crl` extension
* PEM file format with `.crl.pem` extension

## CRL location
CRL locations are detailed in [CA Cert Locations](locations.md)

## Enable certificate revocation
CRLs are always published, however the ability to revoke a certificate needs to be enabled. If you followed the [Getting Started](getting-started.md) guide, you'll already have done this:

* add a subdirectory to your repository with the same name as the value of the Terraform variable `env`, e.g. `dev`, `prd`
add files and subdirectory following the [rsa-public-crl example](https://github.com/serverless-ca/terraform-aws-ca/blob/main/examples/rsa-public-crl/README.md)
* change the value of Terraform variable `cert_info_files` to  `["tls", "revoked", "revoked-root-ca"]`
* apply Terraform

## Revoking a certificate

* identify serial number by inspecting the certificate, or looking up in DynamoDB table
* add details of certificate to be revoked to the `revoked.json` list for relevant environment, e.g. `certs/dev/revoked.json`
```json
[
  {
    "common_name" : "test-tls-cert.example.com",
    "serial_number": "400591262296335747457420220526770623344507066427"
  }
]
```
* run the pipeline
* wait up to 24 hours, or manually execute the CA Step Function
* the revoked certificate can be viewed within the CRL:

![Revoked certificate](assets/images/crl-revoked.png?raw=true)

## CRL publication frequency
If required, the default CRL publication frequency of once per day can be changed, as described in [Configuration Options](./options.md#crl-publication-frequency)

## CRL lifetime
If required, the default CRL lifetime of 1 day plus a 600 seconds overlap period can be changed, as described in [Configuration Options](./options.md#crl-lifetime)