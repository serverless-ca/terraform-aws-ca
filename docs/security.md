# Security
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Automation](automation.md) | [Security](security.md) | [FAQ](faq.md) |  

It's very important to implement your certificate authority (CA) in a secure way:

* each CA should be in a dedicated AWS account
* carefully select CA options for this module:
    * use ECDSA algorithms rather than RSA (default)
    * don't make CRL public unless needed (default)
    * review other options from a security perspective
* very carefully control AWS IAM principals and permissions 
* restrict permissions allowing invocation of all Lambda functions
* store user / device private keys in hardware if possible
* always verify person or entity requesting certificate is authorised
* limit access to CA source code repository and CI/CD pipeline
* ensure updates to CA source code repository are reviewed, especially new Certificate Signing Requests (CSRs)
* monitor CloudTrail for suspicious events, e.g. unauthorised signing using a CA KMS asymmetric key
* export CloudTrail and CloudWatch logs to a central SIEM
* create rules to alert on potential attacks, e.g. CloudTrail event showing CA KMS signing not correlated to Lambda function log in CloudWatch
* update the CA regularly and ensure no vulnerable dependencies
* run regular security scans on CA AWS accounts or link to a CSPM
* consider an independent security review of the CA infrastructure and applications using certificates issued by the CA


The security of any CA is dependent on the protection of CA private keys. AWS KMS is used to generate and store the asymmetric key pair for each CA, with no export of the private key allowed. The hardware security modules (HSMs) used by the AWS KMS service are [FIPS 140-2 level 3 certified](https://aws.amazon.com/about-aws/whats-new/2023/05/aws-kms-hsm-fips-security-level-3/) in all AWS commercial regions except China, which uses OSCCA certified HSMs.

Secure operation of AWS services such as KMS rely on AWS upholding its side of the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/).

The above information is provided to assist you in assuring the security of your CA. However, the authors accept no responsibility for your CA being implemented and operated in a secure manner, in according with the [License](../LICENSE.md).
