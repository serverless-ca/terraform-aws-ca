import boto3
import pytest
import structlog

from assertpy import assert_that
from datetime import datetime
from utils.modules.certs.crypto import crypto_tls_cert_signing_request, create_csr_info
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from .helper import helper_generate_kms_private_key

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()


def _get_dynamodb_table_name():
    """Discover the CA DynamoDB table name from a TLS Lambda's environment variables"""
    lambda_client = boto3.client("lambda")
    lambdas = lambda_client.list_functions()["Functions"]
    tls_lambda = [la for la in lambdas if "-tls-" in la["FunctionName"]][0]

    config = lambda_client.get_function_configuration(FunctionName=tls_lambda["FunctionName"])
    env_vars = config["Environment"]["Variables"]

    project = env_vars["PROJECT"]
    env_name = env_vars["ENVIRONMENT_NAME"]

    capitalised_project = project.replace("-", " ").title().replace(" ", "")
    capitalised_env_name = env_name.title()
    return f"{capitalised_project}CA{capitalised_env_name}"


def _expiry_lambda_exists():
    """Check if the expiry Lambda function has been deployed"""
    lambda_client = boto3.client("lambda")
    lambdas = lambda_client.list_functions()["Functions"]
    return any("-expiry-" in la["FunctionName"] for la in lambdas)


def _query_dynamodb_certificate(table_name, common_name, serial_number):
    """Query DynamoDB for a specific certificate by common name and serial number"""
    client = boto3.client("dynamodb")
    response = client.query(
        TableName=table_name,
        KeyConditionExpression="CommonName = :cn AND SerialNumber = :sn",
        ExpressionAttributeValues={
            ":cn": {"S": common_name},
            ":sn": {"S": serial_number},
        },
    )
    items = response.get("Items", [])
    return items[0] if items else None


def _find_latest_certificate(table_name, common_name):
    """Find the certificate with the latest expiry for a common name"""
    client = boto3.client("dynamodb")
    response = client.query(
        TableName=table_name,
        KeyConditionExpression="CommonName = :cn",
        ExpressionAttributeValues={":cn": {"S": common_name}},
    )
    items = response.get("Items", [])
    if not items:
        return None

    return max(items, key=lambda c: datetime.strptime(c["Expires"]["S"], "%Y-%m-%d %H:%M:%S"))


def _issue_cert_via_direct_invoke(common_name, lifetime=1, notify_expiry=None, notify_issued=None):
    """Issue a certificate via direct Lambda invocation with base64 CSR data"""
    private_key = helper_generate_kms_private_key("-tls-keygen")
    csr_info = create_csr_info(common_name)
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    import base64

    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64.b64encode(csr).decode("utf-8"),
        "lifetime": lifetime,
        "force_issue": True,
    }

    if notify_expiry is not None:
        json_data["notify_expiry"] = notify_expiry

    if notify_issued is not None:
        json_data["notify_issued"] = notify_issued

    function_name = get_lambda_name("-tls")
    log.info("issuing certificate via direct invocation", function_name=function_name, common_name=common_name)
    response = invoke_lambda(function_name, json_data)
    log.info("TLS lambda response", response=response)

    return response


def test_direct_invoke_with_notify_expiry_stores_attribute():
    """
    Test that issuing a certificate with notify_expiry=True stores NotifyExpiry=true in DynamoDB.
    """
    common_name = "pipeline-test-notify-expiry-true.example.com"

    response = _issue_cert_via_direct_invoke(common_name, notify_expiry=True)
    assert_that(response).contains_key("CertificateInfo")
    serial_number = response["CertificateInfo"]["SerialNumber"]
    log.info("certificate issued", common_name=common_name, serial_number=serial_number)

    table_name = _get_dynamodb_table_name()
    cert = _query_dynamodb_certificate(table_name, common_name, serial_number)

    assert_that(cert).is_not_none()
    assert_that(cert).contains_key("NotifyExpiry")
    assert_that(cert["NotifyExpiry"]["BOOL"]).is_true()
    log.info("NotifyExpiry attribute verified as true", common_name=common_name)


def test_direct_invoke_without_notify_expiry_stores_false():
    """
    Test that issuing a certificate without notify_expiry (direct invocation default)
    stores NotifyExpiry=false in DynamoDB.
    """
    common_name = "pipeline-test-notify-expiry-default.example.com"

    response = _issue_cert_via_direct_invoke(common_name)
    assert_that(response).contains_key("CertificateInfo")
    serial_number = response["CertificateInfo"]["SerialNumber"]
    log.info("certificate issued", common_name=common_name, serial_number=serial_number)

    table_name = _get_dynamodb_table_name()
    cert = _query_dynamodb_certificate(table_name, common_name, serial_number)

    assert_that(cert).is_not_none()
    assert_that(cert).contains_key("NotifyExpiry")
    assert_that(cert["NotifyExpiry"]["BOOL"]).is_false()
    log.info("NotifyExpiry attribute verified as false", common_name=common_name)


def test_direct_invoke_with_notify_expiry_gets_expiry_reminder():
    """
    Test that a direct invocation certificate with notify_expiry=True and a 1-day lifetime
    is processed by the expiry Lambda, resulting in an ExpiryReminders entry in DynamoDB.
    """
    if not _expiry_lambda_exists():
        pytest.skip("Expiry Lambda function not deployed")

    common_name = "pipeline-test-notify-expiry-reminder.example.com"

    response = _issue_cert_via_direct_invoke(common_name, lifetime=1, notify_expiry=True)
    assert_that(response).contains_key("CertificateInfo")
    serial_number = response["CertificateInfo"]["SerialNumber"]
    log.info("certificate issued", common_name=common_name, serial_number=serial_number)

    # invoke expiry Lambda
    expiry_function_name = get_lambda_name("-expiry")
    log.info("invoking expiry lambda", function_name=expiry_function_name)
    invoke_lambda(expiry_function_name, {})

    # verify ExpiryReminders was recorded
    table_name = _get_dynamodb_table_name()
    cert = _find_latest_certificate(table_name, common_name)

    assert_that(cert).is_not_none()
    assert_that(cert).contains_key("ExpiryReminders")

    expiry_reminders = cert["ExpiryReminders"]["L"]
    log.info("ExpiryReminders recorded", common_name=common_name, reminders=expiry_reminders)
    assert_that(len(expiry_reminders)).is_greater_than_or_equal_to(1)


def test_direct_invoke_without_notify_expiry_no_expiry_reminder():
    """
    Test that a direct invocation certificate without notify_expiry (defaults to false)
    is NOT processed by the expiry Lambda, so no ExpiryReminders entry in DynamoDB.
    """
    if not _expiry_lambda_exists():
        pytest.skip("Expiry Lambda function not deployed")

    common_name = "pipeline-test-no-notify-expiry-reminder.example.com"

    response = _issue_cert_via_direct_invoke(common_name, lifetime=1)
    assert_that(response).contains_key("CertificateInfo")
    serial_number = response["CertificateInfo"]["SerialNumber"]
    log.info("certificate issued", common_name=common_name, serial_number=serial_number)

    # invoke expiry Lambda
    expiry_function_name = get_lambda_name("-expiry")
    log.info("invoking expiry lambda", function_name=expiry_function_name)
    invoke_lambda(expiry_function_name, {})

    # verify no ExpiryReminders was recorded
    table_name = _get_dynamodb_table_name()
    cert = _query_dynamodb_certificate(table_name, common_name, serial_number)

    assert_that(cert).is_not_none()
    assert_that(cert).does_not_contain_key("ExpiryReminders")
    log.info("confirmed no ExpiryReminders for non-notify cert", common_name=common_name)


def test_direct_invoke_with_notify_issued():
    """
    Test that issuing a certificate with notify_issued=True via direct invocation succeeds.
    The SNS publish happens inside the Lambda - a failure would cause the Lambda to error.
    """
    common_name = "pipeline-test-notify-issued.example.com"

    response = _issue_cert_via_direct_invoke(common_name, notify_issued=True)
    assert_that(response).contains_key("CertificateInfo")
    assert_that(response["CertificateInfo"]["CommonName"]).is_equal_to(common_name)
    log.info("certificate issued with notify_issued=True", common_name=common_name)
