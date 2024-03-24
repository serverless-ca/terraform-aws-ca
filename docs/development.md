# Development

## Python Development

A guide to developing the Python code used in this project is provided in the [Lambda submodule README](https://github.com/serverless-ca/terraform-aws-ca/blob/main/modules/terraform-aws-ca-lambda/README.MD).

## Terraform Development

Notes on Terraform development are included in the [Example README](https://github.com/serverless-ca/terraform-aws-ca/blob/main/examples/default/README.md).

## Documentation Development

Terraform docs and MKDocs are used to produce the [Project Documentation](https://serverlessca.com).

To view the site locally during development:

create virtual environment
```
python -m venv .venv
```
activate virtual environment
```
source .venv/bin/activate
```
install dependencies
```
pip install -r requirements-dev.txt
```
start mkdocs server
```
mkdocs serve
```
view the web site locally at http://127.0.0.1:8000

![Alt text](assets/images/docs-development.png?raw=true "Docs development")
