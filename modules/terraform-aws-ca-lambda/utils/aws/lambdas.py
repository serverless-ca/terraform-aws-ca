import boto3
import json


def get_lambda_name(lambda_purpose):
    """
    Get the full name of the Lambda function based on its purpose
    """

    lambda_client = boto3.client("lambda")

    lambdas = lambda_client.list_functions()["Functions"]
    lambdas = [la for la in lambdas if lambda_purpose in la["FunctionName"]]

    return lambdas[0]["FunctionName"]


def invoke_lambda(function_name, json_data):
    """
    Invoke TLS certificate Lambda function
    """

    lambda_client = boto3.client("lambda")

    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=json.dumps(json_data),
    )

    return json.loads(response["Payload"].read().decode("utf-8"))
