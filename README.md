# Terraform module for Certificate Authority on AWS
* Serverless Certificate Authority typically $50 per year
* Equivalent cost using AWS Private CA $10,000 per year
* 100% serverless
* CA private keys stored in FIPS-140-2 level 3 hardware
* Wide range of configuration options
* Open source with Apache 2.0 license

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