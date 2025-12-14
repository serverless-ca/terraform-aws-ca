# Terraform submodule for AWS Lambda
* Deploys AWS Lambda functions forming part of serverless CA solution
* Submodule of terraform-aws-ca

## Lambda functions
* create_root_ca - creates a root CA
* create_issuing_ca - creates an issuing CA
* issuing_ca_crl - creates a CRL for an issuing CA
* root_ca_crl - creates a CRL for a root CA
* tls_cert - creates a TLS certificate

### tls_cert
#### Input

| Property              | Type                  | Default           | Description                                                                          |
|-----------------------|-----------------------|-------------------|--------------------------------------------------------------------------------------|
| `common_name`         | `Optional[str]`       | `None`            | The `CN` part of the certificate subject. Only optional if `ca_chain_only` is `True` |
| `locality`            | `Optional[str]`       | `None`            | The `L` part of the certificate subject                                              |
| `organization`        | `Optional[str]`       | `None`            | The `O` part of the certificate subject                                              |
| `organizational_unit` | `Optional[str]`       | `None`            | The `OU` part of the certificate subject                                             |
| `country`             | `Optional[str]`       | `None`            | The `C` part of the certificate subject                                              |
| `email_address`       | `Optional[str]`       | `None`            | The `1.2.840.113549.1.9.1` part of the certificate subject                           |
| `state`               | `Optional[str]`       | `None`            | The `ST` part of the certificate subject                                             |
| `lifetime`            | `Optional[int]`       | `30`              | The lifetime of the generated certificate. In days.                                  |
| `purposes`            | `Optional[list[str]]` | `["client_auth"]` | The purposes to use the certificate for, e.g. `server_auth` or `client_auth`         |
| `sans`                | `Optional[list[str]]` | `None`            | Subject Alternative Names. Invalid DNS names will be ignored.                        |
| `ca_chain_only`       | `Optional[bool]`      | `False`           | Return only the root and issuing CA.                                                 |
| `csr_file`            | `Optional[str]`       | `None`            | A path to S3 object, relative to the `INTERNAL_S3_BUCKET` environment variable       |
| `force_issue`         | `Optional[bool]`      | `False`           | Force issue of certificate when private key has already been used                    |
| `cert_bundle`         | `Optional[bool]`      | `False`           | Include Root and Issuing CA in the returned certificate                              |
| `base64_csr_data`     | `Optional[str]`       | `None`            | Base64 encoded CSR that will be used to generate the certificate                     |


#### Output
If `ca_chain_only` is `True`:

| Property                     | Type  | Description                                                                              |
|------------------------------|-------|------------------------------------------------------------------------------------------|
| `Base64RootCaCertificate`    | `str` | Base64 encoded PEM containing the Root CA certificate                                    |
| `Base64IssuingCaCertificate` | `str` | Base64 encoded PEM containing the Issuing CA certificate                                 |
| `Base64CaChain`              | `str` | Base64 encoded PEM containing the Root and Issuing CA certificates. Issuing CA is first. |

Otherwise:

| Property                       | Type   | Description                                                                                                                |
|--------------------------------|--------|----------------------------------------------------------------------------------------------------------------------------|
| `CertificateInfo`              | `dict` | Contains the certificate information                                                                                       |
| `CertificateInfo.CommonName`   | `str`  | The common name used to generate the certificate                                                                           |
| `CertificateInfo.SerialNumber` | `str`  | The serial number of the certificate                                                                                       |
| `CertificateInfo.Issued`       | `str`  | The date the certificate was issued, in the format `2021-01-01 00:00:00`                                                   |
| `CertificateInfo.Expires`      | `str`  | The date the certificate expires in the format `2022-01-01 00:00:00`                                                       |
| `Base64Certificate`            | `str`  | Base64 encoded PEM containing the certificate. If `cert_bundle` was `True` then contents also contains issuing and root CA |
| `Subject`                      | `str`  | The subject string of the generated certificate                                                                            |
| `Base64RootCaCertificate`      | `str`  | Base64 encoded PEM containing the Root CA certificate                                                                      |
| `Base64IssuingCaCertificate`   | `str`  | Base64 encoded PEM containing the Issuing CA certificate                                                                   |
| `Base64CaChain`                | `str`  | Base64 encoded PEM containing the Root and Issuing CA certificates. Issuing CA is first.                                   |


## Local Python development - MacOS / Linux
* create virtual environment
```bash
cd modules\terraform-aws-ca-lambda
python -m venv .venv
```
* activate virtual environment
```bash
source .venv/bin/activate
```
* install dependencies
```powershell
pip install -r requirements-dev.txt
```
* set environment variables for dev environment
```bash
export DOMAIN="ca.example.com"
export ENVIRONMENT_NAME="dev"
export EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-dev"
export INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-dev"
ISSUING_CA_INFO=$(jq -n '{}')
export ISSUING_CA_INFO
export ISSUING_CRL_DAYS="1"
export ISSUING_CRL_SECONDS="600"
export MAX_CERT_LIFETIME="365"
export PROJECT="serverless"
ROOT_CA_INFO=$(jq -n '{country: "GB", state: "London", lifetime: 7300, locality: "London", organization: "serverless", organizationalUnit: "Security Operations", commonName: "Serverless Development Root CA", emailAddress: "secops@example.com", pathLengthConstraint: 1}')
export ROOT_CA_INFO
export PUBLIC_CRL="disabled"
export ROOT_CRL_DAYS="1"
export ROOT_CRL_SECONDS="600"
```
* copy and paste AWS macOS / Linux CLI variables to terminal

* test Lambda function locally
* enter `python`
```python
from lambda_code.create_root_ca.create_root_ca import lambda_handler
lambda_handler({},{})
```
* Test TLS lambda
* Create Certificate Signing Request (CSR) file `client-cert-request.csr` following instructions in [Client Certificates](../../docs/client-certificates.md)
* Upload CSR file to `csrs` folder in Internal S3 bucket
```bash
export DOMAIN="ca.example.com"
export ENVIRONMENT_NAME="dev"
export EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-dev"
export INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-dev"
ISSUING_CA_INFO=$(jq -n '{country: "GB", state: "London", lifetime: 3650, locality: "London", organization: "serverless", organizationalUnit: "Security Operations", commonName: "Serverless Development Issuing CA", emailAddress: "secops@example.com", pathLengthConstraint: 0}')
export ISSUING_CA_INFO
export ISSUING_CRL_DAYS="1"
export ISSUING_CRL_SECONDS="600"
export MAX_CERT_LIFETIME="365"
export PROJECT="serverless"
export PUBLIC_CRL="disabled"
ROOT_CA_INFO=$(jq -n '{}')
export ROOT_CA_INFO
export ROOT_CRL_DAYS="1"
export ROOT_CRL_SECONDS="600"
export SNS_TOPIC_ARN="arn:aws:sns:<REGION>:<ACCOUNT-ID>:serverless-ca-notifications-dev"
```
* copy and paste AWS Powershell CLI variables to terminal
* enter `python`
```python
from lambda_code.tls_cert.tls_cert import lambda_handler
lambda_handler({"common_name": "test-client-cert","lifetime": 1,"csr_file": "client-cert-request.csr","force_issue": True},{})
```
* similar test with customised org and org unit
```python
from lambda_code.tls_cert.tls_cert import lambda_handler
lambda_handler({"common_name": "test-client-cert", "organization": "Acme Inc.", "organizational_unit": "Animation Department","lifetime": 1,"csr_file": "client-cert-request.csr","force_issue": True},{})
```
* unit testing, format and linting checks
```commandline
pytest -v .
black --line-length 120 .
prospector
bandit -r lambda_code utils
```
* Test Issuing CRL lambda
```bash
export AWS_DEFAULT_REGION="eu-west-2"
export ENVIRONMENT_NAME="prod"
export EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-prod"
export INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-prod"
ISSUING_CA_INFO=$(jq -n '{country: "GB", state: "London", lifetime: 3650, locality: "London", organization: "My Company", organizationalUnit: "Security Operations", commonName: "My Company Issuing CA", emailAddress: "secops@example.com", pathLengthConstraint: 0}')
export ISSUING_CA_INFO
export ISSUING_CRL_DAYS="1"
export ISSUING_CRL_SECONDS="600"
export MAX_CERT_LIFETIME="365"
export PROJECT="serverless"
export PUBLIC_CRL="enabled"
ROOT_CA_INFO=$(jq -n '{}')
export ROOT_CA_INFO
export ROOT_CRL_DAYS="1"
export ROOT_CRL_SECONDS="600"
export SNS_TOPIC_ARN="arn:aws:sns:<REGION>:<ACCOUNT-ID>:serverless-ca-notifications-prod"
```
* test Lambda function
```python
from lambda_code.issuing_ca_crl.issuing_ca_crl import lambda_handler
lambda_handler({},{})
```
* download and view CRL
```
curl -s http://ca.example.com/serverless-issuing-ca.crl | openssl crl -inform DER -text -noout
```

## Local Python development - Windows
* create virtual environment
```powershell
cd modules\terraform-aws-ca-lambda
python -m venv .venv
```
* activate virtual environment
```powershell
.venv\Scripts\Activate
```
* install dependencies
```powershell
pip install -r requirements-dev.txt
```
* set environment variables for dev environment
```powershell
$Env:DOMAIN="ca.example.com"
$Env:ENVIRONMENT_NAME="dev"
$Env:EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-dev"
$Env:INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-dev"
$Env:ISSUING_CA_INFO=(@{} | ConvertTo-Json)
$Env:ISSUING_CRL_DAYS="1"
$Env:ISSUING_CRL_SECONDS="600"
$Env:MAX_CERT_LIFETIME="365"
$Env:PROJECT="serverless"
$Env:ROOT_CA_INFO=(@{country = "GB"; state = "London"; lifetime = 7300; locality = "London"; organization = "serverless"; organizationalUnit = "Security Operations"; commonName = "Serverless Development Root CA"; emailAddress = "secops@example.com"; pathLengthConstraint = 1} | ConvertTo-Json)
$Env:ROOT_CRL_DAYS="1"
$Env:ROOT_CRL_SECONDS="600"
$Env:SNS_TOPIC_ARN="arn:aws:sns:<REGION>:<ACCOUNT-ID>:serverless-ca-notifications-dev"
```
* copy and paste AWS Powershell CLI variables to terminal

* test Lambda function locally
* enter `python`
```python
from lambda_code.create_root_ca.create_root_ca import lambda_handler
lambda_handler({},{})
```
* Test TLS lambda
* Create Certificate Signing Request (CSR) file `client-cert-request.csr` following instructions in [Client Certificates](../../docs/client-certificates.md)
* Upload CSR file to `csrs` folder in Internal S3 bucket
```powershell
$Env:DOMAIN="ca.example.com"
$Env:ENVIRONMENT_NAME="dev"
$Env:EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-dev"
$Env:INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-dev"
$Env:ISSUING_CA_INFO=(@{country = "GB"; state = "London"; lifetime = 3650; locality = "London"; organization = "serverless"; organizationalUnit = "Security Operations"; commonName = "Serverless Development Issuing CA"; emailAddress = "secops@example.com"; pathLengthConstraint = 0} | ConvertTo-Json)
$Env:ISSUING_CRL_DAYS="1"
$Env:ISSUING_CRL_SECONDS="600"
$Env:MAX_CERT_LIFETIME="365"
$Env:PROJECT="serverless"
$Env:PUBLIC_CRL="enabled"
$Env:ROOT_CA_INFO=(@{} | ConvertTo-Json)
$Env:ROOT_CRL_DAYS="1"
$Env:ROOT_CRL_SECONDS="600"
```
* copy and paste AWS Powershell CLI variables to terminal
* enter `python`
```python
from lambda_code.tls_cert.tls_cert import lambda_handler
lambda_handler({"common_name": "test-client-cert","lifetime": 1,"csr_file": "client-cert-request.csr","force_issue": True},{})
```
* similar test with customised org and org unit
```python
from lambda_code.tls_cert.tls_cert import lambda_handler
lambda_handler({"common_name": "test-client-cert", "organization": "Acme Inc.", "organizational_unit": "Animation Department","lifetime": 1,"csr_file": "client-cert-request.csr","force_issue": True},{})
```
* unit testing, format and linting checks
```commandline
pytest -v .
black --line-length 120 .
prospector
bandit -r lambda_code utils
```
* Test Issuing CRL lambda
```powershell
$Env:AWS_DEFAULT_REGION="eu-west-2"
$Env:ENVIRONMENT_NAME="prod"
$Env:EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-prod"
$Env:INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-prod"
$Env:ISSUING_CA_INFO=(@{country = "GB"; state = "London"; lifetime = 3650; locality = "London"; organization = "serverless"; organizationalUnit = "Security Operations"; commonName = "My Company Issuing CA"; emailAddress = "secops@example.com"; pathLengthConstraint = 0} | ConvertTo-Json)
$Env:ISSUING_CRL_DAYS="1"
$Env:ISSUING_CRL_SECONDS="600"
$Env:MAX_CERT_LIFETIME="365"
$Env:PROJECT="serverless"
$Env:PUBLIC_CRL="enabled"
$Env:ROOT_CA_INFO=(@{} | ConvertTo-Json)
$Env:ROOT_CRL_DAYS="1"
$Env:ROOT_CRL_SECONDS="600"
$Env:SNS_TOPIC_ARN="arn:aws:sns:<REGION>:<ACCOUNT-ID>:serverless-ca-notifications-prod"
```
* test Lambda function
```python
from lambda_code.issuing_ca_crl.issuing_ca_crl import lambda_handler
lambda_handler({},{})
```
* download and view CRL
```
curl -s http://ca.example.com/serverless-issuing-ca.crl | openssl crl -inform DER -text -noout
```