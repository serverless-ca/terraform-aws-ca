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

    execution_details = stepfunctions_client.describe_execution(executionArn=execution_arn)

    while execution_details["status"] == "RUNNING":
        execution_details = stepfunctions_client.describe_execution(executionArn=execution_arn)
        print(f'"CA Step Function status: {execution_details["status"]}')
        sleep(5)

    return execution_details


if __name__ == "__main__":
    step_function_arn, step_function_name = get_ca_step_function_details()
    print(f"Starting {step_function_name}...")
    execution_arn = start_ca_step_function(step_function_arn)["executionArn"]
    execution_details = monitor_step_function_execution(execution_arn)

    exec_status = execution_details["status"]
    if exec_status == "SUCCEEDED":
        print(f"Step Function {step_function_name} completed successfully")

    if exec_status == "FAILED":
        print(f"Step Function Output: {execution_details}")
        raise SystemExit(f"Step Function {step_function_name} failed")
