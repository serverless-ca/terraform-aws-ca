# Getting Started

| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [FAQ](faq.md) |  
To familiarise yourself with the serverless CA, we recommend you start with minimal changes to the default settings. A Root CA and Issuing CA will be deployed to your AWS account, using ECDSA algorithms without public CRL distribution:

* copy the [default example folder](../examples/default) to your laptop
* make sure you include the `dev` subfolder and contents
* update `backend.tf` to include your own S3 Terraform state bucket in the same AWS account
* update `ca.tf` with the provider source address and latest version
* uncomment the other variables in `ca.tf`
* uncomment `locals.tf` and enter your own company details
```
terraform init
terraform apply (yes to confirm plan)
```
* CA lambda functions, KMS keys, S3 buckets and other resources will be created in your AWS account
* to initialise the CA, use the console to execute the CA Step Functions workflow

<img src="images/step-function.png" width="300">

* alternatively wait for the next scheduled run of the Step Function which may take up to 24 hours

## View CA certificates and CRLs
* CA certificates and CRLs are available in the 'external' S3 bucket created by Terraform

<img src="images/external-s3.png" width="400">

* download the Root CA and issuing CA
* import and trust both CA certificates

## Create client certificate
* ensure Python and PIP are installed on your laptop
* log in to the CA AWS account with your terminal using AWS CLI, e.g. `aws sso login` or set AWS environment variables
* from the root of this repository:
```
python -m venv .venv
source .venv/bin/activate (Linux / MacOS)
.venv/scripts/activate (Windows PowerShell)
pip install -r tests/requirements-dev.txt
python tests/client-cert.py
```
* you will now have a client key and certificate at `~/certs`
* bundled Root CA and Issuing CA certs are also provided

## View client certificate
* view the client certificate `serverless-cert.crt` with your operating system cert viewer

<img src="images/trusted-cert.png" width="300">
<img src="images/cert-details.png" width="300">
<img src="images/cert-chain.png" width="300">

## Create server certificate
* create a server certificate with Subject Alternative Names
```
python tests/server-cert.py
```