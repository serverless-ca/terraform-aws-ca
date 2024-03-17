<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_ca_cloudfront"></a> [ca\_cloudfront](#module\_ca\_cloudfront) | ./modules/terraform-aws-ca-cloudfront | n/a |
| <a name="module_cloudfront_certificate"></a> [cloudfront\_certificate](#module\_cloudfront\_certificate) | ./modules/terraform-aws-ca-acm | n/a |
| <a name="module_create_issuing_ca_iam"></a> [create\_issuing\_ca\_iam](#module\_create\_issuing\_ca\_iam) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_create_root_ca_iam"></a> [create\_root\_ca\_iam](#module\_create\_root\_ca\_iam) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_create_rsa_issuing_ca_lambda"></a> [create\_rsa\_issuing\_ca\_lambda](#module\_create\_rsa\_issuing\_ca\_lambda) | ./modules/terraform-aws-ca-lambda | n/a |
| <a name="module_create_rsa_root_ca_lambda"></a> [create\_rsa\_root\_ca\_lambda](#module\_create\_rsa\_root\_ca\_lambda) | ./modules/terraform-aws-ca-lambda | n/a |
| <a name="module_db-reader-role"></a> [db-reader-role](#module\_db-reader-role) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_dynamodb"></a> [dynamodb](#module\_dynamodb) | ./modules/terraform-aws-ca-dynamodb | n/a |
| <a name="module_external_s3"></a> [external\_s3](#module\_external\_s3) | ./modules/terraform-aws-ca-s3 | n/a |
| <a name="module_internal_s3"></a> [internal\_s3](#module\_internal\_s3) | ./modules/terraform-aws-ca-s3 | n/a |
| <a name="module_issuing_crl_iam"></a> [issuing\_crl\_iam](#module\_issuing\_crl\_iam) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_kms_rsa_issuing_ca"></a> [kms\_rsa\_issuing\_ca](#module\_kms\_rsa\_issuing\_ca) | ./modules/terraform-aws-ca-kms | n/a |
| <a name="module_kms_rsa_root_ca"></a> [kms\_rsa\_root\_ca](#module\_kms\_rsa\_root\_ca) | ./modules/terraform-aws-ca-kms | n/a |
| <a name="module_kms_tls_keygen"></a> [kms\_tls\_keygen](#module\_kms\_tls\_keygen) | ./modules/terraform-aws-ca-kms | n/a |
| <a name="module_root_crl_iam"></a> [root\_crl\_iam](#module\_root\_crl\_iam) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_rsa_issuing_ca_crl_lambda"></a> [rsa\_issuing\_ca\_crl\_lambda](#module\_rsa\_issuing\_ca\_crl\_lambda) | ./modules/terraform-aws-ca-lambda | n/a |
| <a name="module_rsa_root_ca_crl_lambda"></a> [rsa\_root\_ca\_crl\_lambda](#module\_rsa\_root\_ca\_crl\_lambda) | ./modules/terraform-aws-ca-lambda | n/a |
| <a name="module_rsa_tls_cert_lambda"></a> [rsa\_tls\_cert\_lambda](#module\_rsa\_tls\_cert\_lambda) | ./modules/terraform-aws-ca-lambda | n/a |
| <a name="module_scheduler"></a> [scheduler](#module\_scheduler) | ./modules/terraform-aws-ca-scheduler | n/a |
| <a name="module_scheduler-role"></a> [scheduler-role](#module\_scheduler-role) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_step-function"></a> [step-function](#module\_step-function) | ./modules/terraform-aws-ca-step-function | n/a |
| <a name="module_step-function-role"></a> [step-function-role](#module\_step-function-role) | ./modules/terraform-aws-ca-iam | n/a |
| <a name="module_tls_keygen_iam"></a> [tls\_keygen\_iam](#module\_tls\_keygen\_iam) | ./modules/terraform-aws-ca-iam | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_s3_object.cert_info](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.csrs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_logs"></a> [access\_logs](#input\_access\_logs) | Enable access logs for S3 buckets, requires log\_bucket variable to be set | `bool` | `false` | no |
| <a name="input_aws_principals"></a> [aws\_principals](#input\_aws\_principals) | List of ARNs for AWS principals allowed to assume DynamoDB reader role or execute the tls\_cert lambda | `list` | `[]` | no |
| <a name="input_bucket_prefix"></a> [bucket\_prefix](#input\_bucket\_prefix) | first part of s3 bucket name to ensure uniqueness, if left blank a random suffix will be used instead | `string` | `""` | no |
| <a name="input_cert_info_files"></a> [cert\_info\_files](#input\_cert\_info\_files) | List of file names to be uploaded to internal S3 bucket for processing | `list` | `[]` | no |
| <a name="input_csr_files"></a> [csr\_files](#input\_csr\_files) | List of CSR file names to be uploaded to internal S3 bucket for processing | `list` | `[]` | no |
| <a name="input_env"></a> [env](#input\_env) | Environment name, e.g. dev | `string` | `"dev"` | no |
| <a name="input_filter_pattern"></a> [filter\_pattern](#input\_filter\_pattern) | Filter pattern for CloudWatch logs subscription filter | `string` | `""` | no |
| <a name="input_hosted_zone_domain"></a> [hosted\_zone\_domain](#input\_hosted\_zone\_domain) | Hosted zone domain, e.g. dev.ca.example.com | `string` | `""` | no |
| <a name="input_hosted_zone_id"></a> [hosted\_zone\_id](#input\_hosted\_zone\_id) | Hosted zone ID for public zone, e.g. Z0123456XXXXXXXXXXX | `string` | `""` | no |
| <a name="input_issuing_ca_info"></a> [issuing\_ca\_info](#input\_issuing\_ca\_info) | Issuing CA certificate information | `map` | <pre>{<br>  "commonName": "Serverless Issuing CA",<br>  "country": "GB",<br>  "emailAddress": null,<br>  "lifetime": 3650,<br>  "locality": "London",<br>  "organization": "Serverless",<br>  "organizationalUnit": "IT",<br>  "pathLengthConstraint": null,<br>  "state": "London"<br>}</pre> | no |
| <a name="input_issuing_ca_key_spec"></a> [issuing\_ca\_key\_spec](#input\_issuing\_ca\_key\_spec) | Issuing CA key specification | `string` | `"ECC_NIST_P256"` | no |
| <a name="input_issuing_crl_days"></a> [issuing\_crl\_days](#input\_issuing\_crl\_days) | Number of days before Issuing CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval | `number` | `1` | no |
| <a name="input_issuing_crl_seconds"></a> [issuing\_crl\_seconds](#input\_issuing\_crl\_seconds) | Number of seconds before Issuing CA CRL expires, in addition to days. Used for overlap in case of clock skew | `number` | `600` | no |
| <a name="input_kms_arn_resource"></a> [kms\_arn\_resource](#input\_kms\_arn\_resource) | KMS key ARN used for general resource encryption, different from key used for CA key protection | `string` | `""` | no |
| <a name="input_kms_key_alias"></a> [kms\_key\_alias](#input\_kms\_key\_alias) | KMS key alias for bucket encryption, if left at default, TLS key gen KMS key will be used | `string` | `""` | no |
| <a name="input_log_bucket"></a> [log\_bucket](#input\_log\_bucket) | Name of log bucket, if access\_logs variable set to true | `string` | `""` | no |
| <a name="input_logging_account_id"></a> [logging\_account\_id](#input\_logging\_account\_id) | AWS Account ID of central logging account for CloudWatch subscription filters | `string` | `""` | no |
| <a name="input_memory_size"></a> [memory\_size](#input\_memory\_size) | Standard memory allocation for Lambda functions | `number` | `128` | no |
| <a name="input_prod_envs"></a> [prod\_envs](#input\_prod\_envs) | List of production environment names, used in outputs.tf | `list` | <pre>[<br>  "prd",<br>  "prod"<br>]</pre> | no |
| <a name="input_project"></a> [project](#input\_project) | abbreviation for the project, forms first part of resource names | `string` | `"serverless"` | no |
| <a name="input_public_crl"></a> [public\_crl](#input\_public\_crl) | Whether to make the CRL and CA certificates publicly available | `bool` | `false` | no |
| <a name="input_root_ca_info"></a> [root\_ca\_info](#input\_root\_ca\_info) | Root CA certificate information | `map` | <pre>{<br>  "commonName": "Serverless Root CA",<br>  "country": "GB",<br>  "emailAddress": null,<br>  "lifetime": 7300,<br>  "locality": "London",<br>  "organization": "Serverless",<br>  "organizationalUnit": "IT",<br>  "pathLengthConstraint": null,<br>  "state": "London"<br>}</pre> | no |
| <a name="input_root_ca_key_spec"></a> [root\_ca\_key\_spec](#input\_root\_ca\_key\_spec) | Root CA key specification | `string` | `"ECC_NIST_P384"` | no |
| <a name="input_root_crl_days"></a> [root\_crl\_days](#input\_root\_crl\_days) | Number of days before Root CA CRL expires, in addition to seconds. Must be greater than or equal to Step Function interval | `number` | `1` | no |
| <a name="input_root_crl_seconds"></a> [root\_crl\_seconds](#input\_root\_crl\_seconds) | Number of seconds before Root CA CRL expires, in addition to days. Used for overlap in case of clock skew | `number` | `600` | no |
| <a name="input_runtime"></a> [runtime](#input\_runtime) | Lambda language runtime | `string` | `"python3.12"` | no |
| <a name="input_s3_aws_principals"></a> [s3\_aws\_principals](#input\_s3\_aws\_principals) | List of AWS Principals to allow access to external S3 bucket | `list` | `[]` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | Step function schedule in cron format, interval should normally be the same as issuing\_crl\_days | `string` | `"cron(15 8 * * ? *)"` | no |
| <a name="input_subscription_filter_destination"></a> [subscription\_filter\_destination](#input\_subscription\_filter\_destination) | CloudWatch log subscription filter destination, last section of ARN | `string` | `""` | no |
| <a name="input_timeout"></a> [timeout](#input\_timeout) | Amount of time Lambda Function has to run in seconds | `number` | `180` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ca_bundle_s3_location"></a> [ca\_bundle\_s3\_location](#output\_ca\_bundle\_s3\_location) | n/a |
| <a name="output_cloudfront_domain_name"></a> [cloudfront\_domain\_name](#output\_cloudfront\_domain\_name) | n/a |
| <a name="output_issuing_ca_cert_s3_location"></a> [issuing\_ca\_cert\_s3\_location](#output\_issuing\_ca\_cert\_s3\_location) | n/a |
| <a name="output_issuing_ca_crl_s3_location"></a> [issuing\_ca\_crl\_s3\_location](#output\_issuing\_ca\_crl\_s3\_location) | n/a |
| <a name="output_root_ca_cert_s3_location"></a> [root\_ca\_cert\_s3\_location](#output\_root\_ca\_cert\_s3\_location) | n/a |
| <a name="output_root_ca_crl_s3_location"></a> [root\_ca\_crl\_s3\_location](#output\_root\_ca\_crl\_s3\_location) | n/a |
<!-- END_TF_DOCS -->