import boto3
import json
import os


def ca_project():
    """Optional project name filter, set the CA_PROJECT environment variable to target one
    of several CA deployments (e.g. serverless, pqc) sharing the same AWS account"""
    return os.environ.get("CA_PROJECT")


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

    if session is None:
        lambda_client = boto3.client("lambda")
    else:
        lambda_client = session.client("lambda")

    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=json.dumps(json_data),
    )

    return json.loads(response["Payload"].read().decode("utf-8"))
