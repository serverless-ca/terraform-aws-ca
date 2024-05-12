# AWS Application Load Balancer mTLS with open-source cloud CA

A step-by-step guide on implementing mTLS for AWS Application Load Balancer using our [open-source cloud CA](https://github.com/serverless-ca/terraform-aws-ca), also published as a [blog post](https://medium.com/@paulschwarzenberger/aws-application-load-balancer-mtls-with-open-source-cloud-ca-277cb40d60c7).

![Alt text](../assets/images/alb/alb-mtls.png?raw=true "ALB mTLS Architecture")

## Introduction

At re:Invent 2023 AWS [announced support](https://aws.amazon.com/blogs/aws/mutual-authentication-for-application-load-balancer-to-reliably-verify-certificate-based-client-identities) for client certificate authentication to Application Load Balancer. This requires a private Certificate Authority (CA) to issue client certificates to authorise users or systems to access the Application Load Balancer using mutual Transport Layer Security (mTLS).

We use our [open-source serverless cloud CA](https://serverlessca.com), a cost-effective, secure private CA which is straightforward to deploy as a Terraform module.

# Deploy Application Load Balancer without authentication

We’ll start by setting up an Application Load Balancer open to the world. While we’d never actually do this for a confidential application, it’s useful to do so here for demonstration and learning purposes.

> 💰💰💰 the environment you’re creating is relatively costly to run for long periods, so you may wish to complete the setup in one sitting and then destroy, as described at the end of this article

![Alt text](../assets/images/alb/alb-resources.png?raw=true "ALB Deployed Resources")

The following resources will be deployed to your AWS account:

* Certificate in AWS Certificate Manager
* VPC with 2 DMZ subnets and 2 private subnets
* 2 NAT Gateways
* 2 EC2 instances in an auto-scaling group
* Application Load Balancer
* Certificate for ALB in AWS Certificate Manager

You’ll need to already have a public Route53 Hosted Zone in your AWS account, and a S3 bucket for Terraform state.
```
git clone https://github.com/serverless-ca/alb.git
```
* update `backend.tf` with your Terraform state S3 bucket details
* duplicate `terraform.tfvars.example` and rename without the `.example` suffix
* enter values for the fully qualified domain name to be used by the demo application, and the Zone ID of your public hosted zone in Route53
```
cd alb
terraform init
terraform workspace new dev
terraform plan
terraform apply
```

In the AWS console, view the application load balancer and ensure a healthy status under the resource map view:

![Alt text](../assets/images/alb/alb-resource-map.png?raw=true "ALB Resource Map")

## Test Application Load Balancer without authentication

Using a web browser, browse to the domain name you specified:

![Alt text](../assets/images/alb/hello-with-border.png?raw=true "Application Hello")

## Implement open-source serverless CA

If you haven’t already, set up the open-source serverless CA as detailed in the [Getting Started guide](https://serverlessca.com/getting-started). From a security perspective, a production CA should be in a dedicated AWS account, separate from the AWS account used for the Application Load Balancer.

In this case, you’ll need to update the serverless CA Terraform configuration to allow the AWS Service Role for ELB in your application AWS account to access the CA bundle in the external S3 bucket within your CA AWS account.

First obtain the ARN of the ELB service role in your application AWS account by navigating to IAM and searching for AWSServiceRoleForElasticLoadBalancing, for example:
```
arn:aws:iam::012345678901:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing
```

Then add in the optional variable below when calling the serverless CA Terraform module, and then deploy using Terraform.
```
s3_aws_principals = ["arn:aws:iam::<YOUR-APP-ACCOUNT-ID>:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"]
```
See the [Cloud CA repository](https://github.com/serverless-ca/cloud-ca) as an example of how this can be done in practice.

The above configuration step isn’t required if you installed the Application Load Balancer in the same AWS account as the serverless CA.

## Create EC2 Trust Store

We’ll do the next steps manually, for the purposes of understanding and learning. However in a real environment, these should all be implemented using infrastructure-as-code such as Terraform.

* EC2, Load Balancers, Trust Stores, Create Trust Store
* Enter a name for the Trust Store and the S3 bundle URI

![Alt text](../assets/images/alb/trust-store-config.png?raw=true "Trust Store Configuration")

* Press Create Trust Store

After a few minutes, the new Trust Store should be shown as active:

![Alt text](../assets/images/alb/trust-store-created.png?raw=true "Trust Store Created")

## Configure Application Load Balancer certificate authentication

* Select the Application Load Balancer, HTTPS:443 listener, Security:

![Alt text](../assets/images/alb/listener-no-mtls.png?raw=true "ALB Listener without mTLS")

* Edit secure listener settings

![Alt text](../assets/images/alb/edit-listener.png?raw=true "Edit ALB Listener Settings")

* tick the Mutual authentication (mTLS) checkbox
* select Verify with Trust Store
* don’t allow expired client certificates
* choose the Trust Store created earlier from the drop-down

![Alt text](../assets/images/alb/mtls-config.png?raw=true "ALB mTLS Configuration")

* press Save Changes

## Test Application Load Balancer without client certificate

Now it’s time to test.

Browse to your domain name as before. The message you receive may vary according to your browser type. Using Firefox:

![Alt text](../assets/images/alb/firefox-cert-needed.png?raw=true "Test Connection without Certificate")

As you can see, it’s no longer possible to access the application without a valid client certificate.

## Obtain client certificate

* issue a client certificate to your laptop using the utils\client-cert.py script as described in the serverless CA [Getting Started guide](https://serverlessca.com/getting-started)
* this will create the following files in your home directory:

```
certs/client-key.pem
certs/client-cert.pem
certs/client-cert.crt
certs/client-cert-key.pem
```

## Test application load balancer with client certificate

We’ll use Postman to test client certificate authentication, to avoid having to import the certificate into the operating system key store.

* install Postman, then open

You’ll be invited to create an on-line account with Postman, however this isn’t necessary for the tests we’re doing.

* select Settings, Certificates, Client Certificates, Add Certificate
* enter the fully qualified domain name for your application
* navigate to the client-cert.crt and client-key.pem files

![Alt text](../assets/images/alb/postman-settings.png?raw=true "Postman Certificate Settings")

* press Add
* close Settings
* Send a GET request to your domain name
* press Preview

![Alt text](../assets/images/alb/postman-hello.png?raw=true "Successful Certificate Authentication to ALB")

👏 🎉 🎊 Congratulations, you’ve set up and tested Application Load Balancer client authentication with the open-source serverless CA 🎆 🌟 🎇

## Destroy your environment
The environment you’ve created is relatively costly to run for long periods of time, so destroy it once you’ve finished testing.

From within the alb directory:
```
terraform destroy
```
* type yes to confirm when prompted

You’ll still be left with the EC2 Trust Store in your AWS account, however there’s no cost associated with this. You can delete the Trust Store manually via the console if it’s no longer required.
