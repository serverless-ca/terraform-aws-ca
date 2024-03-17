# Frequently Asked Questions
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Automation](automation.md) | [Security](security.md) | [FAQ](faq.md) |  

### Can certificates only be used in AWS?
No, certificates issued by the CA can be used anywhere.

### Can the CA publish a CRL?
The CA publishes a Certificate Revocation List (CRL) to the `external` S3 bucket once every 24 hours by default.
In spite of its name, this bucket has no public access by default.

### I don't want to make any information public, is this possible?
Yes, this is the default setting.

### I'd like to make the CRL publicly available, can I do this?
Yes, this can be done by setting the `public_crl` variable to `true` in the Terraform configuration, and providing a value for the `hosted_zone_name` and `hosted_zone_id` variables.
This will result in a CloudFront distribution, Route53 record and AWS Certificate Manager (ACM) certificate being created.
It will also result in a CRL Distribution Point (CDP) extension being added to the CA certificate and issued certificates.

### Can CA certificates be made publicly available?
Yes, CA certificates are made publicly available if the `public_crl` variable is set to `true` in the Terraform configuration and a value for the `hosted_zone_name` variable included.
This will result in a CloudFront distribution, Route53 record and AWS Certificate Manager (ACM) certificate being created.
It will also result in a Authority Information Access (AIA) extension being added to the CA certificate and issued certificates

### Does the CA support OCSP?
No, OSCP is not currently supported

### What algorithms can be used for the CAs?
The following algorithms can be selected via Terraform [variables](../variables.tf):
`RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521`

### How are the CA private keys protected?
The CA private keys are generated and stored in AWS KMS, and cannot be exported.
The AWS KMS service is [certified to FIPS 140-2 Level 3](https://aws.amazon.com/about-aws/whats-new/2023/05/aws-kms-hsm-fips-security-level-3).

### What's the default configuration for the CA?
The default configuration is:
* `ECC_NIST_P256` for Issuing CA key, `ECC_NIST_P384` Root CA key
* 10 year lifetime for Issuing CA, 20 year lifetime for Root CA
* No public CRLs

### I only want a single CA, not a hierarchy, is this possible?
Not at this time, the only currently supported configuration is an Issuing CA and Root CA.

### I need additional levels of hierarchy in the CA, is this possible?
Not at this time, the only currently supported configuration is an Issuing CA and Root CA.

### Can I use the CA for cross-signing?
Not at this time, the only currently supported configuration is an Issuing CA and Root CA.

### How did you work out the cost comparison with AWS Private CA?

![Alt text](images/costs.png?raw=true "Typical CA costs")

The monthly AWS cost for the AWS accounts used for the CI/CD GitHub Actions tests of this repository are typically $3 without a hosted zone and CloudFront, and $4 with a hosted zone and CloudFront (above). Over 100 certificates are typically issued per month, due to the CI/CD tests. 

The majority of AWS costs are the 3 KMS keys per environment.

Taking the upper figure of $4, the yearly cost is therefore $48, so around $50 per year per CA environment, each CA environment consisting of a Root CA and an Issuing CA.

As of 12 February 2024, [pricing of AWS Private CA](https://aws.amazon.com/private-ca/pricing) is $400 per month per general purpose CA, plus $0.75 per certificate

The monthly cost for a Root CA and Issuing CA plus 100 certificates per month is therefore $875 per month (2 x $400 + 100 x $0.75) or $10,500 per year.

### Can I specify certificate purposes?
You can use the `purposes` JSON key to specify the certificate purposes extension. This overrides any setting in the Certificate Signing Request (CSR). Client Authentication and Server Authentication are supported.

To specify only the client authentication extension:
```json
"purposes": ["client_auth"],
```
To specify only the server authentication extension:
```json
"purposes": ["server_auth"],
```
To specify both client and server authentication extensions:
```json
"purposes": ["client_auth", "server_auth"],
```
If `purposes` isn't specified, the certificate will only include the client authentication extension.

### How can I change CRL lifetime?
The default setting for CRL lifetime of 1 day should be appropriate for most use cases. However, the Issuing CA CRL lifetime, Root CA CRL lifetime, and publication frequency can be adjusted as detailed in [Revocation](revocation.md#crl-lifetime).
