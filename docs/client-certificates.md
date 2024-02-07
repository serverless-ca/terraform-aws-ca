# Client Certificates
| [Home](index.md) | [Getting Started](getting-started.md) | [Client Certificates](client-certificates.md) | [CRL](revocation.md) | [CA Cert Locations](locations.md) | [FAQ](faq.md) |  

There are two methods available for requesting and issuing client certificates:
* **GitOps** - certificates requested and issued via a GitOps workflow
* **Lambda** - certificates requested and issued by invoking a Lambda function

## GitOps
**Example use case** 
* External partner requires a certificate with a manual approval step  

**Example workflow**
* External partner emails Certificate Signing Request (CSR) to internal team
* Internal team adds the CSR to a new branch
* Internal team creates and approves pull request (PR)
* Merge PR to initiate CA pipeline
* Certificate issued and published to DynamoDB table

**Adding CSR File to CA repository**
* In the example below replace `dev` with your environment name
* Add CSR file `server-example-com.csr` to `certs/dev/csrs`
* add JSON to `certs/dev/tls.json` to specify certificate details, e.g.
```json
[
  {
    "common_name": "server.example.com",
    "sans": ["server.example.com", "server2.example.com"]
    "lifetime": 365,
    "csr_file": "server-example-com.csr"
  }
]
```

## Lambda - Amazon EKS or ECS

**Example use case - Amazon EKS / ECS**
* Client certificates for containers in Amazon EKS / ECS / Fargate 

**Approach - Amazon ECS / EKS**
* Create a Sidecar container based on [client-cert.py](../tests/server-cert.py)
* Requires role with permissions to invoke the CA TLS Lambda function
* Certificate, CA bundle and private key should be written to e.g. `/certs` with locked-down folder permissions
* They can then be mounted into the application container

## Lambda - developer testing

**Example use case - developer testing**
* A developer wishes to test mutual TLS from a laptop

**Approach - developer testing**
* Follow instructions at the end of [GettingStarted](getting-started.md)
* Developer needs an IAM role with permissions to invoke the CA TLS Lambda function

## Subject Alternative Names
If you don't specify and DNS names by omitting the optional `sans` entry within the JSON, the common name will be used provided it's a valid domain.

If you specify `sans` these will take precedence over the common name.

Only valid domains will be included in the Subject Alternative Name X.509 certificate extension.