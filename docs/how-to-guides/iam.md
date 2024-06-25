# AWS IAM Roles Anywhere with open-source private CA

A step-by-step guide on implementing AWS IAM Roles Anywhere using our [open-source private CA](https://github.com/serverless-ca/terraform-aws-ca), also published as a [blog post](https://medium.com/@paulschwarzenberger/aws-iam-roles-anywhere-with-open-source-private-ca-6c0ec5758b2b).

![Alt text](../assets/images/iam/aws-iam-roles-anywhere.png?raw=true "ALB IAM Roles Anywhere Architecture")

## Introduction

In 2022 AWS [released AWS IAM Roles Anywhere](https://aws.amazon.com/about-aws/whats-new/2022/07/aws-identity-access-management-iam-roles-anywhere-workloads-outside-aws) introducing certificate authentication as a new way of connecting from on-premise servers to AWS, as an alternative to using secret access keys.

## Implement open-source serverless CA

If you haven’t already, set up the open-source serverless CA as detailed in the [Getting Started](https://serverlessca.com/getting-started/) guide. From a security perspective, a production CA should be in a dedicated AWS account, separate from the AWS account in which you’re setting up AWS IAM Roles Anywhere. I’ll refer to the two AWS accounts as the *CA* and *Application* AWS accounts respectively.

## Download certificate Bundle

* In your CA AWS account, select S3
* Choose the S3 bucket with `external` included in the name

![Alt text](../assets/images/iam/download-bundle.png?raw=true "Download certificate bundle")

* Download the CA bundle, in the above example `serverless-ca-bundle-dev.pem`
* The buncle consists of the Root CA and Issuing CA certificates, combined into a single file
* Open with a text editor and copy to your clipboard

## Create Trust Anchor

* Log in to your Application AWS account
* Select IAM, Roles
* Scroll down to Roles Anywhere, Manage

![Alt text](../assets/images/iam/roles-anywhere-intro.png?raw=true "Roles Anywhere setup")

* Create a trust anchor
* Set a name for the trust anchor, e.g. serverless-ca
* Select External certificate bundle
* Paste in the CA certs bundle certs from your clipboard
* Leave notification defaults
* Add tags if desired

![Alt text](../assets/images/iam/create-trust-anchor-1.png?raw=true "Create Trust Anchor")

* Press Create a trust anchor
* Your trust anchor should now be created

![Alt text](../assets/images/iam/trust-anchor-created.png?raw=true "Trust Anchor created")

## Create IAM Role

* Select IAM, Roles, Create role
* Select Custom Trust Policy
* Copy and Paste the trust policy below

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "rolesanywhere.amazonaws.com"
            },
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession",
                "sts:SetSourceIdentity"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/x509Subject/OU": "Security Operations"
                }
            }
        }
    ]
}
```

The optional condition statement requires the client certificate to include the `Security Operations` OU.

* Press Next
* Select the AWS managed policy AmazonS3FullAccess
* This will allow full access to all S3 buckets in your account, we will narrow this down in the next section
* Add a role name `roles-anywhere-s3-full-access`

![Alt text](../assets/images/iam/add-permissions.png?raw=true "Add permissions to role")

* These permissions will be further restricted by the AWS IAM Roles Anywhere profile.
* Press Create Role

## Create Roles Anywhere Profile

The IAM Roles Anywhere profile restricts access to a subset of permissions included in the policy assigned to the IAM role.

* Search for IAM Roles Anywhere
* This will take you to IAM, Roles, Roles Anywhere
* Create a profile
* This is an optional [session policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session) which further limits permissions
* Effective permissions are the intersection of the session and role policies
* Enter a name for the profile, e.g. s3-read-access-single-bucket
* Select the role you created earlier
* Copy and Paste the session policy below
* Replace `<BUCKET_ARN>` with one of your S3 buckets

```json
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":"s3:Get*",
      "Resource":[
        "<BUCKET ARN>",
        "<BUCKET ARN>/*"
      ]
    }
  ]
}
```

![Alt text](../assets/images/iam/profile.png?raw=true "Roles Anywhere profile")

* Press Create a Profile
* You will now see both the Trust Anchor and Profile in the Roles Anywhere configuration

![Alt text](../assets/images/iam/trust-anchor-and-profile.png?raw=true "Roles Anywhere profile")

## Obtain client certificate
* Issue a client certificate to your laptop using the `utils\client-cert.py` script as described in the serverless CA [Getting Started](https://serverlessca.com/getting-started) guide
* This will create the following files in your home directory:

```
certs/client-key.pem
certs/client-cert.pem
certs/client-cert.crt
certs/client-cert-key.pem
```

## Test client certificate and key

### Download AWS IAM Roles Anywhere Credential Helper
* [Download](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) the AWS IAM Roles Anywhere Credential Helper tool for your operating system
* Copy the binary into your home directory
* Alternatively copy to another location, e.g. `usr/bin/local` and set directory in your `PATH`
* if using MacOS, remove file name extended attribute: `xattr -c aws_signing_helper`
* set as executable: `chmod 755 aws_signing_helper`

### Initial Test

```bash
./aws_signing_helper credential-process \
    --certificate certs/client-cert.pem \
    --private-key certs/client-key.pem \
    --trust-anchor-arn "arn:aws:rolesanywhere:eu-west-2:992382525818:trust-anchor/2de9dfa7-9f39-40c2-ae31-aaf843684dc9" \
    --profile-arn "arn:aws:rolesanywhere:eu-west-2:992382525818:profile/86227258-a142-433d-a4bc-6015c99b39b9" \
    --role-arn "arn:aws:iam::992382525818:role/roles-anywhere-s3-full-access"
```

* customise the above with your own ARNs
* from your home directory, copy and paste to your terminal and press Enter
* you should receive a response like this:

```json
{
  "Version":1,
  "AccessKeyId":"XXXXXXXXXXXX",
  "SecretAccessKey":"XXXXXXXXXXXX",
  "SessionToken":"XXXXXXXXXXXX",
  "Expiration":"2024-06-13T21:35:23Z"
}
```

### Set variables automatically
[Roy Ben Yosef’s article](https://medium.com/cyberark-engineering/calling-aws-services-from-your-on-premises-servers-using-iam-roles-anywhere-3e335ed648be) on IAM Roles Anywhere includes a useful script for setting variables automatically.

* create a python script in your home directory named `get_creds.py`:

```python
import json
import syscreds = json.loads(sys.stdin.read())print(f"AWS_ACCESS_KEY_ID={creds['AccessKeyId']} AWS_SECRET_ACCESS_KEY={creds['SecretAccessKey']} AWS_SESSION_TOKEN={creds['SessionToken']}")
```
* And then set all three variables using a single command:

```bash
export $(./aws_signing_helper credential-process \
    --certificate certs/client-cert.pem \
    --private-key certs/client-key.pem \
    --trust-anchor-arn <anchor-arn> \
    --profile-arn <profile-arn> \
    --role-arn <role-arn> | python get_creds.py)
```

* for example:

```bash
export $(./aws_signing_helper credential-process \
    --certificate certs/client-cert.pem \
    --private-key certs/client-key.pem \
    --trust-anchor-arn "arn:aws:rolesanywhere:eu-west-2:992382525818:trust-anchor/2de9dfa7-9f39-40c2-ae31-aaf843684dc9" \
    --profile-arn "arn:aws:rolesanywhere:eu-west-2:992382525818:profile/86227258-a142-433d-a4bc-6015c99b39b9" \
    --role-arn "arn:aws:iam::992382525818:role/roles-anywhere-s3-full-access" | python get_creds.py)
```

* substitute your ARNs
* copy and paste the script to your terminal
* press enter

## Test access

* check AWS identity, this should succeed

```bash
aws sts get-caller-identity
```

* list all S3 buckets, this should fail as access is only allowed to a single bucket

```bash
aws s3 ls
An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
```

* download a file from the designated S3 bucket, this should succeed
* replace the example below with your own S3 bucket and object

```bash
aws s3 cp s3://cloud-apps-confidential/confidential.png confidential.png
download: s3://cloud-apps-confidential/confidential.png to ./confidential.png
```

## View connection details

* At IAM, Roles, Roles Anywhere, navigate to your region
* Select Subject Activity

![Alt text](../assets/images/iam/subject-activity.png?raw=true "Roles Anywhere subject activity")

* A record of connections can be seen
* Click on the link to view the certificate used to authenticate

👏 🎉 🎊 Congratulations, you’ve set up and tested AWS IAM Roles Anywhere with the open-source private CA 🎆 🌟 🎇

## Security Considerations

AWS IAM Roles Anywhere is a useful additional option for granting on-premise and mobile laptops access to AWS. Effectively it replaces AWS access keys with X.509 certificates.

However it’s important to note that this isn’t necessarily any more secure — a stolen certificate and private key can be used to access AWS just as easily as a stolen access key and secret access key.

Whether this is a secure solution depends very much on how the private key of the client certificate is stored. A good approach is to use hardware devices such as Trusted Platform Modules (TPMs) and Yubikeys, both of which are [now supported](https://aws.amazon.com/about-aws/whats-new/2023/09/iam-roles-anywhere-credential-helper-pkcs-11-modules) by the IAM Roles Anywhere credentials helper.

It’s also essential that the Certificate Authority is implemented in a secure manner, as described in [Security](https://serverlessca.com/security/).