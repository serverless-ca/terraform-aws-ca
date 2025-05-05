# Terraform module for Certificate Authority on AWS

[![Version](https://img.shields.io/github/v/release/serverless-ca/terraform-aws-ca)](https://github.com/serverless-ca/terraform-aws-ca/releases/tag/v0.1.0)
[![Build](https://img.shields.io/github/actions/workflow/status/serverless-ca/terraform-aws-ca/.github%2Fworkflows%2Fecdsa_default.yml?branch=main)](https://github.com/serverless-ca/terraform-aws-ca/actions/workflows/ecdsa_default.yml)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/serverless-ca/terraform-aws-ca/blob/main/LICENSE.md)

* Serverless Certificate Authority typically $50 per year
* [Equivalent cost using AWS Private CA around $10,000 per year](https://serverlessca.com/faq/#how-did-you-work-out-the-cost-comparison-with-aws-private-ca)
* 100% serverless
* CA private keys stored in [FIPS 140-2 level 3 certified hardware](https://aws.amazon.com/about-aws/whats-new/2023/05/aws-kms-hsm-fips-security-level-3)
* Wide range of [configuration options](https://serverlessca.com/options/)
* Published as a public [Terraform registry module](https://registry.terraform.io/modules/serverless-ca/ca/aws/latest)

<a href="#"><img src="https://raw.githubusercontent.com/serverless-ca/terraform-aws-ca/main/docs/assets/images/ca-architecture-options.png" /></a>

> 📄 Detailed documentation is on our [Docs](https://serverlessca.com) site. If testing the Serverless CA for the first time, use the [Getting Started](https://serverlessca.com/getting-started/) guide.

> 📢 We welcome contributions! See the [Contributing Guide](https://github.com/serverless-ca/terraform-aws-ca/blob/main/CONTRIBUTING.md) for how to get started.

## Open Cloud Security Conference - talk and demo
<a href="#"><img src="https://raw.githubusercontent.com/serverless-ca/terraform-aws-ca/main/docs/assets/images/open-cloud-security.png" /></a>
Talk and demo on [YouTube](https://youtu.be/p2Cb5PSXWSE)

## SANS CloudSecNext - talk and demo
<a href="#"><img src="https://raw.githubusercontent.com/serverless-ca/terraform-aws-ca/main/docs/assets/images/sans-cloudsecnext.png" /></a>
Talk and demo on [YouTube](https://youtu.be/JJD2GrZxLq4)

## Blog posts
> 📖 [Open-source cloud Certificate Authority](https://medium.com/@paulschwarzenberger/open-source-cloud-certificate-authority-75609439dfe7)

> 📖 [AWS Application Load Balancer mTLS with open-source cloud CA](https://medium.com/@paulschwarzenberger/aws-application-load-balancer-mtls-with-open-source-cloud-ca-277cb40d60c7)

> 📖 [AWS IAM Roles Anywhere with open-source private CA](https://medium.com/@paulschwarzenberger/aws-iam-roles-anywhere-with-open-source-private-ca-6c0ec5758b2b)

> 📖 [API Gateway mTLS with open-source cloud CA](https://medium.com/@paulschwarzenberger/api-gateway-mtls-with-open-source-cloud-ca-3362438445de)

## Sponsors
This project is supported by [Q-Solution](https://www.q-solution.co.uk)

<a href="#"><img src="https://raw.githubusercontent.com/serverless-ca/terraform-aws-ca/main/docs/assets/images/q-solution.png" /></a>
