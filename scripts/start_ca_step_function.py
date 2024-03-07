from boto3 import client
from time import sleep


def get_ca_step_function_details():
    """
    Get ARN and name of CA Step function
    """

    stepfunctions_client = client("stepfunctions")

    step_functions = stepfunctions_client.list_state_machines()["stateMachines"]
    step_function = [s for s in step_functions if "-ca-" in s["name"]]

    return step_function[0]["stateMachineArn"], step_function[0]["name"]


def start_ca_step_function(step_function_arn):
    """
    Start CA Step function
    """

    stepfunctions_client = client("stepfunctions")
    return stepfunctions_client.start_execution(stateMachineArn=step_function_arn)


def monitor_step_function_execution(execution_arn):
    """
    Ensure CA Step Function completes without errors
    """

    stepfunctions_client = client("stepfunctions")

    execution_status = stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]

    while execution_status == "RUNNING":
        execution_status = stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
        print(f"CA Step Function status: {execution_status}")
        sleep(5)

    return execution_status


if __name__ == "__main__":
    step_function_arn, step_function_name = get_ca_step_function_details()
    print(f"Starting {step_function_name}...")
    execution_arn = start_ca_step_function(step_function_arn)["executionArn"]
    execution_status = monitor_step_function_execution(execution_arn)

    if execution_status == "SUCCEEDED":
        print(f"Step Function {step_function_name} completed successfully")

    if execution_status == "FAILED":
        raise SystemExit(f"Step Function {step_function_name} failed")
