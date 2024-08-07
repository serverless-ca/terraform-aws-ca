# API Gateway mTLS with open-source cloud CA

A step-by-step guide on implementing mTLS for Amazon API Gateway using our [open-source private cloud CA](https://github.com/serverless-ca/terraform-aws-ca), also published as a [blog post](https://medium.com/@paulschwarzenberger/api-gateway-mtls-with-open-source-cloud-ca-3362438445de).

![Alt text](../assets/images/api/api-ca-architecture.png?raw=true "API Gateway mTLS Architecture")

## Introduction

Programmatic communications between systems at different organisations usually use APIs, in most cases requiring client authentication before providing an API response. Client certificate authentication is an effective and scalable way of ensuring an API is only available to authorised systems.

Amazon API Gateway can be configured to require mutual Transport Layer Security (mTLS) using client certificate authentication. This requires a private Certificate Authority (CA) to issue client certificates to authorise systems to use the API service. We use our [open-source serverless cloud CA](https://serverlessca.com), a cost-effective, secure private CA which is straightforward to deploy as a Terraform module.

## Deploy API Gateway without authentication

We’ll start by setting up an API Gateway open to the world. While we’d never actually do this for a confidential API, it’s useful to do so here for demonstration and learning purposes.

The following resources will be deployed to your AWS account:

* REST API Gateway
* Lambda function
* CloudWatch log groups
* IAM policies and roles

```bash
git clone https://github.com/serverless-ca/api-gateway.git
```

* update `backend.tf` with your Terraform state S3 bucket details

```bash
cd api-gateway
terraform init
terraform plan
terraform apply
```

In the AWS console, select API Gateway, and view the deployed `cloud-app-api` REST API:

![Alt text](../assets/images/api/api-gateway-no-auth.png?raw=true "API Gateway REST API details")

For the purposes of this how-to guide, we’ll use a Lambda function to provide the response to an API Gateway request.

In the AWS console, choose Lambda, then the `api-response` Lambda function:

![Alt text](../assets/images/api/lambda-function.png?raw=true "API Gateway REST API details")

## Test API Gateway without authentication

Select the API Gateway link from the Lambda console to view trigger details:

![Alt text](../assets/images/api/api-gateway-execution-endpoint.png?raw=true "API Endpoint details shown in Lambda console")

Note that the HTTP method configured is POST, and that the API Gateway is set up with a publicly accessible execute API endpoint, and no authorisation.

Install [Postman](https://www.postman.com/downloads) on your laptop. You’ll be encouraged to open an account with Postman, however you don’t need to for the purposes of this tutorial.

Copy the API Endpoint execute API from the AWS console Lambda trigger details above, choose the POST method, and test:

![Alt text](../assets/images/api/postman-no-auth.png?raw=true "API response with no authentication using Postman")

You should see the message “successful response from API Gateway lambda function”.

## Implement open-source serverless CA

If you haven’t already, set up the [open-source serverless CA](https://serverlessca.com) as detailed in the [Getting Started](../getting-started.md) guide. From a security perspective, a production CA should be in a dedicated AWS account, separate from the AWS account used for the REST API Gateway.

In this case, you’ll need to update the serverless CA Terraform configuration to allow the user or role logged in to the API Gateway AWS account to access the CA bundle in the external S3 bucket within your CA AWS account. For example, if you’re deploying via an IAM user, add in the optional variable below when calling the serverless CA Terraform module, and then deploy using Terraform.

```bash
s3_aws_principals = ["arn:aws:iam::<API_GATEWAY_AWS_ACCOUNT_ID>:user/<YOUR_IAM_USER_NAME>"]
```

See the [Cloud CA repository](https://github.com/serverless-ca/cloud-ca) as an example of how this can be done in practice.

The above configuration step isn’t required if you installed the API Gateway in the same AWS account as the serverless CA.

## Configure custom domain name for API Gateway

We’ll do the next steps manually, for the purposes of understanding and learning. However in a real environment, these should all be implemented using infrastructure-as-code such as Terraform.

From a domain which you own, choose an appropriate subdomain for the API gateway. Then create a TLS certificate using AWS Certificate Manager with DNS validation. This will be the API Gateway server certificate, which doesn’t need to be issued by the serverless private CA.

![Alt text](../assets/images/api/certificate-manager.png?raw=true "AWS Certificate Manager")

* At API Gateway, Custom Domain Names, press Create
* Enter the custom domain name you’ve chosen for your API Gateway
* Slide mutual TLS authentication to on
* Copy the S3 URI of the bundle PEM file in the CA External S3 bucket
* Copy the Version ID of the bundle PEM file in the CA External S3 bucket

![Alt text](../assets/images/api/api-gw-truststore-config.png?raw=true "API Gateway mTLS configuration")

* Choose the ACM certificate issued previously

![Alt text](../assets/images/api/api-gw-acm-config.png?raw=true "Selection of ACM certificate for API Gateway")

* Press Create domain name

## Map API custom domain name to API Gateway

The newly created API custom domain name must now be mapped to the API Gateway created earlier.

* At your newly created API custom domain name, select API mappings
* Press Configure API mappings, Add new mappings
* Select the already configured API Gateway and environment

![Alt text](../assets/images/api/default-api-endpoint-warning.png?raw=true "API Gateway warning of potential mTLS bypass")

* You’ll see a warning that the default execute API endpoint must be disabled to prevent bypass of mutual TLS
* Select the `cloud-app-api` API Gateway, API Settings, Edit
* Change the default endpoint to Inactive

![Alt text](../assets/images/api/default-api-endpoint-inactive.png?raw=true "API Gateway settings with default execute endpoint disabled")

* Press Save changes
* Return to the `cloud-app-api` resources screen

![Alt text](../assets/images/api/deploy-api.png?raw=true "Deploy API")

* Press Deploy API
* Choose the dev stage and press Deploy
* Return to the Add new mapping screen which should no longer show the warning

![Alt text](../assets/images/api/add-new-mapping.png?raw=true "Warning no longer shown")

* Press Save
* View the custom domain name, now configured for mTLS

![Alt text](../assets/images/api/custom-domain-name-configured.png?raw=true "API Gateway custom domain mapping")

## Create DNS entry for API custom domain name

We need to create a public DNS record to the new API custom domain name.

* within Route53 for your hosted zone, create a DNS record for the custom domain name
* the CNAME value should be the API endpoint as listed in the custom domain name configuration

![Alt text](../assets/images/api/dns-record.png?raw=true "Route53 entry for API Gateway custom domain")

## Test default API endpoint disabled

First, let’s confirm that the default execute API endpoint is disabled.

* Open Postman
* Repeat the API call made earlier

![Alt text](../assets/images/api/default-endpoint-failure.png?raw=true "Test using Postman without a certificate results in a 403 response")

* You should see a `"Forbidden"` message
* If you still get the previous response, check you’ve deployed the API

## Test mutual TLS

* Issue a client certificate to your laptop using the utils\client-cert.py script as described in the serverless CA [Getting Started](../getting-started.md) guide
* this will create the following files in your home directory:

```bash
certs/client-key.pem
certs/client-cert.pem
certs/client-cert.crt
certs/client-cert-key.pem
```

* open Postman
* select Settings, Certificates, Client Certificates, Add Certificate
* Enter the custom domain name
* navigate to the `client-cert.crt` and `client-key.pem` files

![Alt text](../assets/images/api/add-certificate.png?raw=true "Configuring Postman with client certificates")

* press Add
* close Settings
* Send a POST request to your custom domain name adding the `/api` path

![Alt text](../assets/images/api/client-auth-success.png?raw=true "Successful response using Postman with client certificate")

* The success message should be returned indicating a successful response

## View certificate details in CloudWatch logs

Details of the connection can be viewed within CloudWatch logs

* view the api-gateway-access CloudWatch log

![Alt text](../assets/images/api/cloudwatch-logs.png?raw=true "API Gateway access logs shows certificate details")

* details of your certificate connection can be viewed

👏 🎉 🎊 Congratulations, you’ve set up and tested API Gateway mTLS with the open-source serverless CA 🎆 🌟 🎇

## Certificate Revocation

Amazon API Gateway mTLS doesn’t by default support Certificate Revocation List (CRL) checking.

This can be implemented using an API Gateway Lambda authorizer, checking against the latest CRL issued by the serverless CA. The Lambda authorizer may also perform additional checks to require the client certificate to have particular certificate distinguished name fields such as a specific Organization Unit (OU).
