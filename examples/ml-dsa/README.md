# Post-Quantum (ML-DSA) Certificate Authority with Public CRL

Deploys a fully post-quantum CA hierarchy using AWS KMS ML-DSA key pairs
([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), X.509 profile per
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)):

* **Root CA**: `ML_DSA_65` (NIST security category 3)
* **Issuing CA**: `ML_DSA_44` (NIST security category 2)
* Public CRL and CA certificates published via CloudFront

All CA private keys are generated and used within AWS KMS FIPS 140-3 Security Level 3
validated HSMs, exactly as for RSA and ECDSA CAs. Certificate, CSR and CRL signing uses
the KMS `ML_DSA_SHAKE_256` signing algorithm with `EXTERNAL_MU` message type, so CRLs of
any size can be signed despite the 4,096-byte KMS `RAW` message limit.

This example is designed to share an AWS account, hosted zone and CloudFront
distribution with another CA deployment (e.g. [rsa-public-crl](../rsa-public-crl)):
it uses project name `pqc` with the same environment name `prod`, so all resource
names are prefixed `pqc-` rather than `serverless-`. Via `external_s3_bucket_name`,
the public CRL and CA certificates are published as `pqc`-prefixed files (e.g.
`http://ca.example.com/pqc-issuing-ca.crl`) to the classical deployment's external
S3 bucket, served by its existing CloudFront distribution at the same domain - no
additional CloudFront distribution, TLS certificate, DNS record or hosted zone.

Via `existing_slack_secret_name`, it also shares that deployment's Slack OAuth token
secret (`serverless-slack-token-prod`), so no second secret is created and the token only
needs to be uploaded once for the account. The notify Lambda is granted `kms:Decrypt` on
the KMS key encrypting the shared secret.

Each deployment here is a separate Terraform configuration with its own state, so the
rsa-public-crl deployment must be applied first: the shared bucket and secret have to
exist before this example is planned. Where two CAs are instead declared as two module
blocks in a single configuration, make the dependency explicit with
`depends_on = [module.certificate_authority]` on the second block, and give it identifiers
known at plan time - the shared bucket name (set `bucket_prefix` so it has no random
suffix) and the shared secret name - so that both CAs can be created by one `apply`.

## End-entity certificates

* CSR flow: fully post-quantum end-entity certificates - generate an ML-DSA key pair
  and CSR with `utils/generate-csr.py` (`generate_key("ml-dsa-44")`) or OpenSSL 3.5+
* No-CSR (GitOps `tls.json`) flow: AWS KMS `GenerateDataKeyPair` doesn't yet support
  ML-DSA, so subject key pairs remain classical (`ECC_NIST_P256`) under the
  post-quantum chain - chain signatures are still quantum-safe

## Compatibility

Relying parties must support ML-DSA certificates: OpenSSL 3.5+, Java 25+, and
`cryptography` 48.0.0+ can verify ML-DSA chains; most AWS managed mTLS services
(ALB, API Gateway, IAM Roles Anywhere) and browsers do not yet accept them.
Check [KMS region availability](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)
of ML-DSA key specs before deploying to a new region.

## Local Development - Terraform

This example uses a `-pqc` suffixed Terraform state key, keeping its state separate
from other deployments sharing the same state bucket. From within this subdirectory:

```
terraform init -backend-config=bucket={YOUR_TERRAFORM_STATE_BUCKET} -backend-config=key=terraform-aws-ca-pqc -backend-config=region={YOUR_TERRAFORM_STATE_REGION}
terraform plan
terraform apply
```

## Local Development - Python

see [Lambda Submodule README](../../modules/terraform-aws-ca-lambda/README.MD)
