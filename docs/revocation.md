# Certificate Revocation

![Alt text](images/crl.png?raw=true "Certificate Revocation List")

* Certificates can be revoked using a Certificate Revocation List (CRL)
* Online Certificate Status Protocol (OCSP) is not supported

## CRL publication
CRLs are published to `external` S3 bucket, not directly accessible from public Internet

To publish publicly, set `public_crl` to `true` and provide `hosted_zone_id` and `hosted_zone_name` in [Terraform variables](https://github.com/serverless-ca/terraform-aws-ca/blob/main/variables.tf).

Applying Terraform will result in:
* CRLs published to a public URL via CloudFront
* CA certificates published to a public URL via CloudFront
* CRL Distribution Point (CDP) extension added to certificates
* Authority Information Access (AIA) extension added to certificates

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
* add details of certificate to be revoked in `revoked.json` for relevant environment, e.g. `certs/dev/revoked.json`
```json
[
  {
    "common_name" : "test-tls-cert.example.com",
    "serial_number": "487548094217404552161959299244142788109493400485"
  },
  {
    "common_name" : "test-tls-cert2.example.com",
    "serial_number": "92003901754314702601432136351765805692836206995"
  }
]
```
* run the pipeline
* wait up to 24 hours, or manually execute the CA Step Function

## CRL publication frequency
If required, the default CRL publication frequency of once per day can be changed, as described in [Configuration Options](./options.md#crl-publication-frequency)

## CRL lifetime
If required, the default CRL lifetime of 1 day plus a 600 seconds overlap period can be changed, as described in [Configuration Options](./options.md#crl-lifetime)