# Terraform module for Certificate Authority on AWS
* Serverless Certificate Authority typically $50 per year
* [Equivalent cost using AWS Private CA around $10,000 per year](./docs/faq.md#how-did-you-work-out-the-cost-comparison-with-aws-private-ca)
* 100% serverless
* CA private keys stored in [FIPS 140-2 level 3 certified hardware](https://aws.amazon.com/about-aws/whats-new/2023/05/aws-kms-hsm-fips-security-level-3)
* Wide range of [configuration options](./docs/options.md)
* Open source with [Apache 2.0 license](./LICENSE.md)

![Alt text](docs/images/ca-architecture-options.png?raw=true "CA architecture")

## Documentation
Detailed documentation is on our [Docs](docs/index.md) site. If testing the Serverless CA for the first time, use the [Getting Started](docs/getting-started.md) guide.

## Contributing
We welcome contributions! See the [Contributing Guide](CONTRIBUTING.md) for how to get started.

See [Example README](./examples/default/README.md) for information on Terraform development and testing.

A guide to development and testing the Lambda function Python code is provided in the [Lambda sub-module README](/modules/terraform-aws-ca-lambda/README.MD).

## Sponsors
This project is supported by [Q-Solution](https://www.q-solution.co.uk)

![Alt text](docs/images/q-solution.png?raw=true "Q-Solution")