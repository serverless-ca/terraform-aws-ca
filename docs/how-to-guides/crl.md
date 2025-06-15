# Revoking access to IAM Roles Anywhere using open-source private CA

A step-by-step guide on revoking access to IAM Roles Anywhere using [open-source private CA](https://github.com/serverless-ca/terraform-aws-ca), also published as a [blog post](https://medium.com/@paulschwarzenberger/revoking-access-to-iam-roles-anywhere-using-open-source-private-ca-47667cc92299).

![Alt text](../assets/images/crl/macbook.png?raw=true "MacBook used for testing revocation")

## Introduction

[IAM Roles Anywhere](https://aws.amazon.com/iam/roles-anywhere) (IAMRA) is an AWS service providing a certificate authentication option for users or machines outside of AWS, to gain permissions within AWS.

For example, an on-premise server might run a daily backup job writing to a S3 bucket, or a mobile medical device could connect via mobile networks to stream health information to a database.

IAMRA requires a certificate authority (CA) to act as a trust store and to issue end user or device certificates. One option is [AWS Private CA](https://aws.amazon.com/private-ca), however this is expensive at $400 per month + $0.75 per certificate.

![Alt text](../assets/images/ca-architecture-options.png?raw=true "Serverless CA architecture")

In 2024 we released an [open-source serverless private cloud CA](https://serverlessca.com) with costs typically under $5 per month, and provided a guide to [setting up IAM Roles Anywhere using the CA](https://medium.com/@paulschwarzenberger/aws-iam-roles-anywhere-with-open-source-private-ca-6c0ec5758b2b).

## Why revocation is important

![Alt text](../assets/images/crl/keys.png?raw=true "Photo by Florian Berger on Unsplash")

For a robust security solution, it’s important to have a method of revoking access, in the event that the user or device certificate private key is compromised — for example if a physical device or server is stolen.

This post provides a walkthrough of how to revoke a certificate using the open-source serverless CA, import the Certificate Revocation List (CRL) to IAMRA, and test.

## Set up CA and connect using IAMRA

Begin by following the [guide to setting up the serverless CA](https://serverlessca.com/getting-started/), and after that, the [guide to configuring IAMRA](https://serverlessca.com/how-to-guides/iam/).

Ensure you reach the point where you execute a command to check AWS identity:

```bash
aws sts get-caller-identity --profile secops
```

You should receive a response like this:
```json
{
    "UserId": "AROA6ODU3UF5DTDLJCYVE:61d5692c1982239b82255b38e6ced2aa34712ff0",
    "Account": "012345678901",
    "Arn": "arn:aws:sts::012345678901:assumed-role/roles-anywhere-s3-full-access/61d5692c1982239b82255b38e6ced2aa34712ff0"
}
```
## Identify certificate details

Now we’re ready to test certificate revocation with IAMRA.

Look up certificate details locally on your laptop:
```bash
openssl x509 -noout -text -in 'certs/client-cert.crt'
```

You should get a response like this:

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:b7:47:12:77:a9:52:91:35:b0:e1:47:cb:94:02:63:b6:37:c1:35
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Cloud Issuing CA, C=GB, L=London, O=Cloud CA, OU=Security Operations
        Validity
            Not Before: Mar 22 07:12:52 2025 GMT
            Not After : Jun 20 07:17:52 2025 GMT
        Subject: CN=My Test Certificate, C=GB, L=London, O=Serverless Inc, OU=Security Operations, ST=England
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:57:f1:ef:92:95:62:61:c9:77:ad:05:ea:68:3f:
                    4f:90:ed:ce:75:a5:93:9d:d8:cb:af:26:4d:77:39:
                    4b:55:c1:26:29:92:ed:11:17:99:53:d2:fe:8e:22:
                    20:4d:f2:67:79:50:7c:4b:54:3c:57:7a:ef:fd:f1:
                    b9:78:26:7e:ef
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.1
            X509v3 Subject Key Identifier: 
                42:55:6E:81:41:62:32:17:81:18:8C:6C:2A:96:04:EF:8D:D0:91:0C
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://certs.cloud-ca.com/serverless-issuing-ca-dev.crl
            Authority Information Access: 
                CA Issuers - URI:http://certs.cloud-ca.com/serverless-issuing-ca-dev.crt
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:16:31:73:9f:00:84:cb:2e:32:75:85:e3:c0:ef:
        af:65:df:e9:f5:af:99:0d:6c:96:74:60:21:c6:4f:bd:03:14:
        02:20:3d:88:7d:5a:6a:b8:5b:fa:4a:81:f2:96:55:3b:ba:3d:
        6b:a9:b7:8a:57:e8:18:84:c6:05:97:74:83:ae:01:2a
```

If the device has recently used IAMRA, certificate details can also be obtained by logging in to the AWS account and region in which IAMRA is configured. Select IAM, Roles Anywhere, Subject Activity:

![Alt text](../assets/images/crl/iamra-recent-cert.png?raw=true "Recent certificates authenticating to IAMRA")

## Create Pull Request

To revoke the certificate, submit a Pull Request to the repository used to deploy the serverless CA with details of the certificate to be revoked, added to `certs/{ENVIRONMENT_NAME}/revoked.json`:

![Alt text](../assets/images/crl/pr-revoke-cert.png?raw=true "Pull Request to revoke certificate")

## Revoke certificate

To revoke the certificate, run the deploy pipeline which will update `revoked.json` in the internal S3 bucket.

Wait till the next scheduled execution of the CA step function, or execute manually or via a pipeline step:

![Alt text](../assets/images/crl/step-function.png?raw=true "Serverless CA Step Function")

## Check CRL

Wou can check the CRL includes the specified certificate by locating the file in the “external” S3 bucket within the CA AWS account. Alternatively if you’re publishing the CRL publicly, download from the CRL distribution point (CDP) for the Issuing CA CRL, e.g. https://certs.cloud-ca.com/serverless-issuing-ca-dev.crl.

The `.crl` file is in DER format, and can readily be viewed on a Windows operating system:

![Alt text](../assets/images/crl/crl.png?raw=true "Serverless CA CRL")

![Alt text](../assets/images/crl/revoked.png?raw=true "Serverless CA revoked certificates")

If you’re using MacOS or Linux, you can view using open SSL:

```bash
openssl crl -text -noout -in ~/Downloads/serverless-issuing-ca-dev.crl -inform DER
```
```bash
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Cloud Issuing CA, C=GB, L=London, O=Cloud CA, OU=Security Operations
        Last Update: Jun  1 10:24:36 2025 GMT
        Next Update: Jun  2 10:34:36 2025 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                60:3D:CE:88:8A:1C:82:BF:10:8A:A6:40:76:9F:DD:38:1A:E5:1E:87
            X509v3 CRL Number: 
                531
Revoked Certificates:
    Serial Number: 462B222A8B9773A090F3778F29B5D5BB9DEF983B
        Revocation Date: Feb 22 20:16:26 2024 GMT
    Serial Number: 22B7471277A9529135B0E147CB940263B637C135
        Revocation Date: Jun  1 10:24:35 2025 GMT
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:aa:45:58:96:e4:03:71:57:0e:2f:9d:8e:6d:
        0b:d7:a2:ef:60:73:23:8f:08:22:77:80:c7:cf:8f:b1:c8:08:
        20:02:21:00:cd:b9:e7:a6:98:c0:65:27:13:05:c6:92:0d:1c:
        b3:56:7d:db:77:2c:37:63:31:76:8e:e2:26:ca:09:45:e3:38
```

## Download CRL in PEM format

The serverless CA publishes CRLs in both DER format with a `.crl` file extension, and in PEM format with `.crl.pem` extension.

If your serverless CA CRL is public, download the CRL in PEM format from the location for the Issuing CA CRL, e.g. https://certs.cloud-ca.com/serverless-issuing-ca-dev.crl.pem.

Otherwise, locate and download the file from the “external” S3 bucket.

## Import CRL to IAM Roles Anywhere

At the present time, there’s no visibility of the CRL functionality for IAMRA within the AWS console, so we need to use the AWS CLI or other AWS SDK.

In the AWS account in which you’ve configured IAMRA, import the CRL in PEM format, for example:

```bash
aws rolesanywhere import-crl --crl-data $(base64 -i ~/Downloads/serverless-issuing-ca-dev.crl.pem) --name "Serverless Issuing CA Dev" --trust-anchor-arn "arn:aws:rolesanywhere:eu-west-2:012345678901:trust-anchor/2de9dfa7-9f39-40c2-ae31-aaf843684dc9" --output json
```
Example response:
```json
{
    "crl": {
        "createdAt": "2025-06-01T14:20:10.510727+00:00",
        "crlArn": "arn:aws:rolesanywhere:eu-west-2:012345678901:crl/3a4d71af-5bc8-4749-a47b-66e9d1e3bd58",
        "crlData": "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tCk1JSUJkakNDQVJzQ0FRRXdDZ1lJS29aSXpqMEVBd0l3YWpFWk1CY0dBMVVFQXd3UVEyeHZkV1FnU1hOemRXbHUKWnlCRFFURUxNQWtHQTFVRUJoTUNSMEl4RHpBTkJnTlZCQWNNQmt4dmJtUnZiakVSTUE4R0ExVUVDZ3dJUTJ4dgpkV1FnUTBFeEhEQWFCZ05WQkFzTUUxTmxZM1Z5YVhSNUlFOXdaWEpoZEdsdmJuTVhEVEkxTURZd01URXdNalF6Ck5sb1hEVEkxTURZd01qRXdNelF6Tmxvd1RqQWxBaFJHS3lJcWk1ZHpvSkR6ZDQ4cHRkVzduZStZT3hjTk1qUXcKTWpJeU1qQXhOakkyV2pBbEFoUWl0MGNTZDZsU2tUV3c0VWZMbEFKanRqZkJOUmNOTWpVd05qQXhNVEF5TkRNMQpXcUF3TUM0d0h3WURWUjBqQkJnd0ZvQVVZRDNPaUlvY2dyOFFpcVpBZHAvZE9CcmxIb2N3Q3dZRFZSMFVCQVFDCkFnSVRNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNxUlZpVzVBTnhWdzR2blk1dEM5ZWk3MkJ6STQ4SUluZUEKeDgrUHNjZ0lJQUloQU0yNTU2YVl3R1VuRXdYR2tnMGNzMVo5MjNjc04yTXhkbzdpSnNvSlJlTTQKLS0tLS1FTkQgWDUwOSBDUkwtLS0tLQo=",
        "crlId": "3a4d71af-5bc8-4749-a47b-66e9d1e3bd58",
        "enabled": false,
        "name": "Serverless Issuing CA Dev",
        "trustAnchorArn": "arn:aws:rolesanywhere:eu-west-2:012345678901:trust-anchor/2de9dfa7-9f39-40c2-ae31-aaf843684dc9",
        "updatedAt": "2025-06-01T14:20:10.510727+00:00"
    }
}
```

## Enable CRL in IAM Roles Anywhere

Enable the new CRL in IAMRA using the crlId value from the previous command response:

```bash
aws rolesanywhere enable-crl --crl-id 3a4d71af-5bc8-4749-a47b-66e9d1e3bd58 --output json
```

Response:

```json
{
    "crl": {
        "createdAt": "2025-06-01T14:20:10.510727+00:00",
        "crlArn": "arn:aws:rolesanywhere:eu-west-2:012345678901:crl/3a4d71af-5bc8-4749-a47b-66e9d1e3bd58",
        "crlData": "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tCk1JSUJkakNDQVJzQ0FRRXdDZ1lJS29aSXpqMEVBd0l3YWpFWk1CY0dBMVVFQXd3UVEyeHZkV1FnU1hOemRXbHUKWnlCRFFURUxNQWtHQTFVRUJoTUNSMEl4RHpBTkJnTlZCQWNNQmt4dmJtUnZiakVSTUE4R0ExVUVDZ3dJUTJ4dgpkV1FnUTBFeEhEQWFCZ05WQkFzTUUxTmxZM1Z5YVhSNUlFOXdaWEpoZEdsdmJuTVhEVEkxTURZd01URXdNalF6Ck5sb1hEVEkxTURZd01qRXdNelF6Tmxvd1RqQWxBaFJHS3lJcWk1ZHpvSkR6ZDQ4cHRkVzduZStZT3hjTk1qUXcKTWpJeU1qQXhOakkyV2pBbEFoUWl0MGNTZDZsU2tUV3c0VWZMbEFKanRqZkJOUmNOTWpVd05qQXhNVEF5TkRNMQpXcUF3TUM0d0h3WURWUjBqQkJnd0ZvQVVZRDNPaUlvY2dyOFFpcVpBZHAvZE9CcmxIb2N3Q3dZRFZSMFVCQVFDCkFnSVRNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNxUlZpVzVBTnhWdzR2blk1dEM5ZWk3MkJ6STQ4SUluZUEKeDgrUHNjZ0lJQUloQU0yNTU2YVl3R1VuRXdYR2tnMGNzMVo5MjNjc04yTXhkbzdpSnNvSlJlTTQKLS0tLS1FTkQgWDUwOSBDUkwtLS0tLQo=",
        "crlId": "3a4d71af-5bc8-4749-a47b-66e9d1e3bd58",
        "enabled": true,
        "name": "Serverless Issuing CA Dev",
        "trustAnchorArn": "arn:aws:rolesanywhere:eu-west-2:012345678901:trust-anchor/2de9dfa7-9f39-40c2-ae31-aaf843684dc9",
        "updatedAt": "2025-06-01T14:22:43.269195+00:00"
    }
}
```

The CRL is now shown as enabled.

## Test certificate revocation

Test by repeating the command used at the beginning of this article:

```bash
aws sts get-caller-identity --profile secops
```

Access is denied to the identity, with the reason “Certificate revoked”.

```bash
Error when retrieving credentials from custom-process: 2025/06/01 15:24:50 AccessDeniedException: Certificate revoked
```

👏 🎉 🎊 Congratulations, you’ve tested certificate revocation for AWS IAM Roles Anywhere with the open-source private CA 🎆 🌟 🎇
