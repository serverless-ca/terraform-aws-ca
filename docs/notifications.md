# Notifications

The Serverless CA module provides SNS notifications for different events. You can directly subscribe to the CA Notifications SNS Topic to receive email notifications.

You can also add your own infrastructure to that provided by the module, and deliver customised messaging to your CA administrators and users, for example:

![Notifications](assets/images/notifications.png)

##  Notification types

| Event                        | GitOps | Lambda Invocation  |
|------------------------------|:------:|:------------------:|
| Certificate Issued           |   ✅    |         -          |
| Certificate Request Rejected |   ✅    |         ✅          |
| Certificate Revoked          |   ✅    |         ✅          |

##  Certificate Issued notification

When a certificate is issued via the GitOps process, a notification is published to the CA Notifications SNS Topic:

![Certificate Issued](assets/images/sns-cert-issued.png)

Certificate Issued notification - example JSON:
```json
{
  "CertificateInfo": {
    "CommonName": "pipeline-test-csr-s3-upload",
    "SerialNumber": "725732270238932467356021650679497159468001185756",
    "Issued": "2026-02-08 08:11:41",
    "Expires": "2026-02-09 08:16:41"
  },
  "Base64Certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNZRENDQWdlZ0F3SUJBZ0lVZng3MTQ3QXc5bnVUR2FwOGJtclZtc0Jxejl3d0NnWUlLb1pJemowRUF3SXcKY1RFZU1Cd0dBMVVFQXd3VlUyVnlkbVZ5YkdWemN5QkpjM04xYVc1bklFTkJNUXN3Q1FZRFZRUUdFd0pIUWpFUApNQTBHQTFVRUJ3d0dURzl1Wkc5dU1STXdFUVlEVlFRS0RBcFRaWEoyWlhKc1pYTnpNUXN3Q1FZRFZRUUxEQUpKClZERVBNQTBHQTFVRUNBd0dURzl1Wkc5dU1CNFhEVEkyTURJd09EQTRNVEUwTVZvWERUSTJNREl3T1RBNE1UWTAKTVZvd2daSXhKREFpQmdOVkJBTU1HM0JwY0dWc2FXNWxMWFJsYzNRdFkzTnlMWE16TFhWd2JHOWhaREVMTUFrRwpBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBY01GVTkyWlhKeWFXUmxJRU5UVWlCTWIyTmhkR2x2YmpFWk1CY0dBMVVFCkNnd1FUM1psY25KcFpHVWdRMU5TSUU5eVp6RVBNQTBHQTFVRUN3d0dSR1YyVDNCek1SRXdEd1lEVlFRSURBaE8KWlhjZ1dXOXlhekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDRFWk44QmZHRHBPZjlmTis5QgpENUFhZGxXSXRyT3dUMVZKRHp0UitCRksrSTk0WjZjZGFLUnBudVdQVTdiYWRGcHJaQ3B2T09OMVNtZGFKSWRnCkRRbWpXekJaTUE0R0ExVWREd0VCL3dRRUF3SUZvREFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQWpBVEJnTlYKSFNBRUREQUtNQWdHQm1lQkRBRUNBVEFkQmdOVkhRNEVGZ1FVamcwM1lZRkxSTVpzS042bjdVMGxKbUVPQnpNdwpDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdUQTVqcVhuTm9IOWZpN1NIanVteW5FdmsyY1lUVW4yWmtDcUJoRlpiCklPUUNJRUpKR21HUHhFcTR1M3UxQ1l0bjhZRjBHT0tQOWpCbWxjWWE1cUdLeXMvRAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
  "Subject": "ST=New York,OU=DevOps,O=Override CSR Org,L=Override CSR Location,C=US,CN=pipeline-test-csr-s3-upload"
}
```

##  Certificate Request Rejected notification

Certificate request rejections result in a SNS Notification. Possible reasons for rejection include:

* CSR must include a Common Name
* Lifetime must be at least 1 day
* Private key has already been used for a certificate

![Certificate Request Rejected](assets/images/sns-csr-rejected.png)

Certificate Request Rejected notification - example JSON:
```json
{
  "CSRInfo": {
    "CommonName": "test-client-cert",
    "Lifetime": 1,
    "Purposes": [
      "client_auth"
    ],
    "SANs": []
  },
  "Base64CSR": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlBqQ0I1QUlCQURDQmdURVlNQllHQTFVRUF3d1BRMnh2ZFdRZ1FYSmphR2wwWldOME1Rc3dDUVlEVlFRRwpFd0pIUWpFUE1BMEdBMVVFQnd3R1RHOXVaRzl1TVJjd0ZRWURWUVFLREE1VFpYSjJaWEpzWlhOeklFbHVZekVjCk1Cb0dBMVVFQ3d3VFUyVmpkWEpwZEhrZ1QzQmxjbUYwYVc5dWN6RVFNQTRHQTFVRUNBd0hSVzVuYkdGdVpEQloKTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCUDNhaU1CVzV5Z0haYmZzbGJvYU0zMDE3b1lKdmI5UApTYzVLVWlZSVMwVFJBcmFNWEZOODVBMVRRRCswMmZyTnR1YnVENTIvNjhwMjBCTnd1Ris5VStDZ0FEQUtCZ2dxCmhrak9QUVFEQWdOSkFEQkdBaUVBOVQ3SGVkaUlpZFlZL2ZnaVNvZHU1bDNQNS9YNGc3MHRhdlQ0SWJPWjBrd0MKSVFEMw5sUTE2SlN5WEtLVmpiSlFLREhGQXhySEE0d3BKQWFjbmV3T0dkV1FqQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=",
  "Subject": "ST=England,OU=Security Operations,O=Serverless Inc,L=London,C=GB,CN=Cloud Architect",
  "Reason": "Private key has already been used for a certificate"
}
```

##  Certificate Revoked notification

A SNS notification is published when a certificate is revoked:

![Certificate Revoked](assets/images/sns-cert-revoked.png)

Certificate Revoked notification - example JSON:
```json
{
  "CommonName": "pipeline-test-csr-s3-upload",
  "SerialNumber": "253508645453578743400361452260705386159413554723",
  "Revoked": "2026-02-03 21:34:04.753865",
  "Subject": "ST=New York,OU=DevOps,O=Override CSR Org,L=Override CSR Location,C=US,CN=pipeline-test-csr-s3-upload"
}
```

##  Cross-account subscription to SNS Topic

To subscribe a Lambda function or other service in a separate account to the CA SNS Topic, set Terraform variables:
```
sns_policy_template = "cross-account"
workload_account_id = "012345678901"
```