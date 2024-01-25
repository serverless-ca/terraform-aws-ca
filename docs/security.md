# Security
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [Options](options.md) | [Security](security.md) | [FAQ](faq.md) |  

It's very important to implement your certificate authority (CA) in a secure way:

* each CA should be in a dedicated AWS account
* carefully select CA options for this module:
    * use ECDSA algorithms rather than RSA (default)
    * don't make CRL public unless needed (default)
    * review other options from a security perspective
* very carefully control AWS IAM principals and permissions 
* restrict permissions allowing invocation of all Lambda functions
* limit access to CA source code repository and CI/CD pipeline
* ensure updates to CA source code repository are reviewed, especially new Certificate Signing Requests (CSRs)
* store user / device private keys in hardware if possible
* monitor CloudTrail for suspicious events, e.g. unauthorised signing using a CA KMS asymmetric key
* export CloudTrail and CloudWatch logs to a central SIEM
* create rules to alert on potential attacks, e.g. CloudTrail event showing CA KMS signing not correlated to Lambda function log in CloudWatch
* update the CA regularly and ensure no vulnerable dependencies
* run regular security scans on CA AWS accounts or link to a CSPM
* consider an independent security review of the CA infrastructure and applications using certificates issued by the CA

The above list is provided to assist you in securing your CA, however the authors accept no responsibility for ensuring your CA is implemented and being operated in a secure manner, in according with the [License](../LICENSE.md).
