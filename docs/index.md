---
title: Terraform module for serverless CA on AWS
description: Serverless CA in AWS with FIPS 140-2 level 3 CA key storage and cost typically under $5 per month
---
# Terraform module for Certificate Authority on AWS

[![Version](https://img.shields.io/github/v/release/serverless-ca/terraform-aws-ca)](https://github.com/serverless-ca/terraform-aws-ca/releases/tag/v0.1.0)
[![Build](https://img.shields.io/github/actions/workflow/status/serverless-ca/terraform-aws-ca/.github%2Fworkflows%2Fecdsa_default.yml?branch=main)](https://github.com/serverless-ca/terraform-aws-ca/actions/workflows/ecdsa_default.yml)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/serverless-ca/terraform-aws-ca/blob/main/LICENSE.md)

* Serverless Certificate Authority typically $50 per year
* [Equivalent cost using AWS Private CA around $10,000 per year](./faq.md#how-did-you-work-out-the-cost-comparison-with-aws-private-ca)
* 100% serverless
* CA private keys stored in [FIPS 140-2 level 3 certified hardware](https://aws.amazon.com/about-aws/whats-new/2023/05/aws-kms-hsm-fips-security-level-3)
* Wide range of [configuration options](options.md)
* Published as a public [Terraform registry module](https://registry.terraform.io/modules/serverless-ca/ca/aws/latest)

![Alt text](assets/images/ca-architecture-options.png?raw=true "CA architecture")

## Blog posts

> 📖 [Open-source cloud Certificate Authority](https://medium.com/@paulschwarzenberger/open-source-cloud-certificate-authority-75609439dfe7)

> 📖 [AWS Application Load Balancer mTLS with open-source cloud CA](https://medium.com/@paulschwarzenberger/aws-application-load-balancer-mtls-with-open-source-cloud-ca-277cb40d60c7)

> 📖 [AWS IAM Roles Anywhere with open-source private CA](https://medium.com/@paulschwarzenberger/aws-iam-roles-anywhere-with-open-source-private-ca-6c0ec5758b2b)

## Sponsors
This project is supported by [Q-Solution](https://www.q-solution.co.uk)

![Alt text](assets/images/q-solution.png?raw=true "Q-Solution")
