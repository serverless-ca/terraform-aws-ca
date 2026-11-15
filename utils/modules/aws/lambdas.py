import boto3
import json
import os
import sys

from botocore.config import Config

# A synchronous Lambda invocation is not idempotent, so it must never be retried automatically.
# The read timeout also needs to exceed the Lambda function's own timeout, so that a slow
# invocation returns its real response rather than timing out client-side.
INVOKE_CONFIG = Config(read_timeout=300, retries={"max_attempts": 0})


def get_lambda_client(session=None):
    """
    Get a Lambda client configured for non-idempotent synchronous invocations
    """

    if session is None:
        return boto3.client("lambda", config=INVOKE_CONFIG)

    return session.client("lambda", config=INVOKE_CONFIG)


def ca_project():
    """Optional project name filter, set the CA_PROJECT environment variable to target one
    of several CA deployments (e.g. serverless, pqc) sharing the same AWS account"""
    return os.environ.get("CA_PROJECT")


def list_ca_projects(session=None):
    """
    List project names of CA deployments in the account, based on TLS certificate Lambda function
    names of the form <project>-tls-cert-<env>
    """
    if session is None:
        lambda_client = boto3.client("lambda")
    else:
        lambda_client = session.client("lambda")

    projects = set()
    for page in lambda_client.get_paginator("list_functions").paginate():
        for la in page["Functions"]:
            if "-tls-cert-" in la["FunctionName"]:
                projects.add(la["FunctionName"].split("-tls-cert-")[0])

    return sorted(projects)


def select_ca_project(session=None):
    """
    Set CA_PROJECT to target one CA deployment, prompting the user to choose if several share
    the AWS account and no project has been specified
    """
    if ca_project():
        return

    projects = list_ca_projects(session=session)
    if len(projects) < 2:
        return

    if not sys.stdin.isatty():
        print(f"Error: multiple CA deployments found ({', '.join(projects)}), specify one with --project")
        sys.exit(1)

    print("Multiple CA deployments found in this AWS account:")
    for number, project in enumerate(projects, start=1):
        print(f"  {number}. {project}")

    while True:
        choice = input(f"Select CA project [1-{len(projects)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(projects):
            choice = projects[int(choice) - 1]
        if choice in projects:
            os.environ["CA_PROJECT"] = choice
            print(f"Using CA project: {choice}")
            return
        print("Invalid selection, please try again")


def get_lambda_name(lambda_purpose, env_name=None, session=None):
    """
    Get the full name of the Lambda function based on its purpose
    """
    if session is None:
        lambda_client = boto3.client("lambda")
    else:
        lambda_client = session.client("lambda")

    lambdas = lambda_client.list_functions()["Functions"]
    if ca_project():
        lambdas = [la for la in lambdas if la["FunctionName"].startswith(f"{ca_project()}-")]
    if env_name is None:
        lambdas = [la for la in lambdas if lambda_purpose in la["FunctionName"]]
    else:
        lambdas = [la for la in lambdas if la["FunctionName"].endswith(f"{lambda_purpose}-{env_name}")]

    return lambdas[0]["FunctionName"]


def invoke_lambda(function_name, json_data, session=None):
    """
    Invoke TLS certificate Lambda function
    """

    lambda_client = get_lambda_client(session)

    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=json.dumps(json_data),
    )

    return json.loads(response["Payload"].read().decode("utf-8"))
