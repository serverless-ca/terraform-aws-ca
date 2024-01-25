# Terraform submodule for AWS Lambda
* Deploys AWS Lambda functions forming part of serverless CA solution
* Submodule of terraform-aws-ca

## Local Python development - Windows
* create virtual environment
```powershell
cd modules\terraform-aws-ca-lambda
python -m venv .venv
```
* activate virtual environment on Windows
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
$Env:PROJECT="serverless"
$Env:ROOT_CA_INFO=(@{country = "GB"; state = "London"; lifetime = 7300; locality = "London"; organization = "serverless"; organizationalUnit = "Security Operations"; commonName = "Serverless Development Root CA"; emailAddress = "secops@example.com"; pathLengthConstraint = 1} | ConvertTo-Json)
```
* copy and paste AWS Powershell CLI variables to terminal
* test Lambda function locally
* enter `python`
```python
from lambda_code.create_root_ca.create_root_ca import lambda_handler
lambda_handler({},{})
```
* Test TLS lambda
```powershell
$Env:DOMAIN="ca.example.com"
$Env:ENVIRONMENT_NAME="dev"
$Env:EXTERNAL_S3_BUCKET="my-company-serverless-ca-external-dev"
$Env:INTERNAL_S3_BUCKET="my-company-serverless-ca-internal-dev"
$Env:ISSUING_CA_INFO=(@{country = "GB"; state = "London"; lifetime = 3650; locality = "London"; organization = "serverless"; organizationalUnit = "Security Operations"; commonName = "Serverless Development Issuing CA"; emailAddress = "secops@example.com"; pathLengthConstraint = 0} | ConvertTo-Json)
$Env:PROJECT="serverless"
$Env:PUBLIC_CRL="enabled"
$Env:ROOT_CA_INFO=(@{} | ConvertTo-Json)
```
* copy and paste AWS Powershell CLI variables to terminal
* enter `python`
```python
from lambda_code.tls_cert.tls_cert import lambda_handler
lambda_handler({"common_name": "test-client-cert","lifetime": 1,"passphrase": False,"force_issue": True},{})
```
* similar test with customised org and org unit
```python
lambda_handler({"common_name": "test-client-cert", "organization": "Acme Inc.", "organizational_unit": "Animation Department","lifetime": 1,"passphrase": False,"force_issue": True},{})
```
* format and linting checks
```commandline
black --line-length 120 .
prospector
bandit -r lambda_code utils
```