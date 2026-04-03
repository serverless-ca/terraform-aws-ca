import boto3
import json
import pytest
import structlog

from assertpy import assert_that
from cryptography.hazmat.primitives.serialization import load_der_private_key
from datetime import datetime
from utils.modules.certs.crypto import crypto_tls_cert_signing_request, create_csr_info
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.aws.s3 import get_s3_bucket, get_s3_object, list_s3_object_keys, put_s3_object

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

COMMON_NAME = "pipeline-expiry-test.example.com"
CSR_FILE = f"{COMMON_NAME}.csr"


def _gitops_enabled():
    """Check if GitOps certificate issuing is enabled by looking for tls.json in internal S3 bucket"""
    bucket_name = get_s3_bucket()
    object_keys = list_s3_object_keys(bucket_name)
    return "tls.json" in object_keys


def _expiry_lambda_exists():
    """Check if the expiry Lambda function has been deployed"""
    try:
        get_lambda_name("-expiry")
        return True
    except IndexError:
        return False


def _get_dynamodb_table_name():
    """Discover the CA DynamoDB table name from the expiry Lambda environment variables"""
    lambda_client = boto3.client("lambda")
    expiry_function_name = get_lambda_name("-expiry")
    config = lambda_client.get_function_configuration(FunctionName=expiry_function_name)
    env_vars = config["Environment"]["Variables"]

    project = env_vars["PROJECT"]
    env_name = env_vars["ENVIRONMENT_NAME"]

    capitalised_project = project.replace("-", " ").title().replace(" ", "")
    capitalised_env_name = env_name.title()
    return f"{capitalised_project}CA{capitalised_env_name}"


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


def _find_latest_expiry_certificate(table_name, common_name):
    """Query all certificates for a common name and return the one with the latest expiry.

    This mirrors the logic in the expiry Lambda's get_latest_certificate function,
    ensuring the test checks the same certificate the Lambda would process.
    """
    client = boto3.client("dynamodb")
    response = client.query(
        TableName=table_name,
        KeyConditionExpression="CommonName = :cn",
        ExpressionAttributeValues={":cn": {"S": common_name}},
    )
    items = response.get("Items", [])
    if not items:
        return None

    latest = max(items, key=lambda c: datetime.strptime(c["Expires"]["S"], "%Y-%m-%d %H:%M:%S"))
    return latest


def _upload_test_csr(bucket_name, kms_arn):
    """Generate and upload a test CSR to S3, return the CSR bytes"""
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)
    csr_info = create_csr_info(COMMON_NAME)
    csr = crypto_tls_cert_signing_request(private_key, csr_info)
    put_s3_object(bucket_name, kms_arn, f"csrs/{CSR_FILE}", csr)
    log.info("uploaded test CSR to S3", bucket=bucket_name, key=f"csrs/{CSR_FILE}")
    return csr


def _append_to_tls_json(bucket_name, kms_arn):
    """Append test certificate entry to tls.json and return original contents for restoration"""
    original_tls_json = json.loads(get_s3_object(bucket_name, "tls.json"))
    log.info("current tls.json", entries=len(original_tls_json))

    # Remove any existing entry for this common name
    updated_tls_json = [entry for entry in original_tls_json if entry.get("common_name") != COMMON_NAME]

    # Append test certificate entry with 1 day lifetime so it matches the "1" expiry reminder setting
    updated_tls_json.append(
        {
            "common_name": COMMON_NAME,
            "country": "GB",
            "locality": "London",
            "organization": "Example Company",
            "organizational_unit": "DevOps",
            "lifetime": 1,
            "csr_file": CSR_FILE,
        }
    )

    put_s3_object(bucket_name, kms_arn, "tls.json", json.dumps(updated_tls_json).encode("utf-8"))
    log.info("updated tls.json with test entry", entries=len(updated_tls_json))
    return original_tls_json


def _restore_tls_json(bucket_name, kms_arn, original_tls_json):
    """Restore tls.json to its original state"""
    put_s3_object(bucket_name, kms_arn, "tls.json", json.dumps(original_tls_json).encode("utf-8"))
    log.info("restored tls.json", entries=len(original_tls_json))


def test_expiry_reminder_sent_and_not_duplicated():
    """
    Test that expiry reminder is sent when certificate is close to expiring,
    and that invoking the expiry lambda again does not send a duplicate reminder.
    Only runs against environments where GitOps certificate issuing is enabled.
    """
    # Skip if GitOps is not enabled or expiry Lambda is not deployed
    if not _gitops_enabled():
        pytest.skip("GitOps certificate issuing not enabled (tls.json not found in S3)")

    if not _expiry_lambda_exists():
        pytest.skip("Expiry Lambda function not deployed")

    # Get S3 bucket and KMS details
    bucket_name = get_s3_bucket()
    _, kms_arn = get_kms_details("-tls-keygen")

    # Save original tls.json and update with test entry
    original_tls_json = _append_to_tls_json(bucket_name, kms_arn)

    try:
        # Step 1: Upload test CSR to S3
        _upload_test_csr(bucket_name, kms_arn)

        # Step 2: Issue the certificate via TLS Lambda
        tls_function_name = get_lambda_name("-tls")
        json_data = {
            "common_name": COMMON_NAME,
            "country": "GB",
            "locality": "London",
            "organization": "Example Company",
            "organizational_unit": "DevOps",
            "lifetime": 1,
            "csr_file": CSR_FILE,
            "force_issue": True,
        }
        log.info("issuing test certificate", function_name=tls_function_name, json_data=json_data)
        tls_response = invoke_lambda(tls_function_name, json_data)
        log.info("TLS lambda response", response=tls_response)

        assert_that(tls_response).contains_key("CertificateInfo")
        serial_number = tls_response["CertificateInfo"]["SerialNumber"]
        log.info("test certificate issued", serial_number=serial_number, common_name=COMMON_NAME)

        # Step 3: Invoke the expiry reminder Lambda
        expiry_function_name = get_lambda_name("-expiry")
        log.info("invoking expiry lambda (first time)", function_name=expiry_function_name)
        expiry_response = invoke_lambda(expiry_function_name, {})
        log.info("expiry lambda response (first invocation)", response=expiry_response)

        # Step 4: Look up the certificate the expiry Lambda would have processed.
        # The Lambda picks the certificate with the latest expiry for the common name,
        # which may not be the one just issued if previous test runs left older certs
        # with later expiry times in DynamoDB.
        table_name = _get_dynamodb_table_name()
        latest_cert = _find_latest_expiry_certificate(table_name, COMMON_NAME)
        latest_serial = latest_cert["SerialNumber"]["S"]
        log.info(
            "latest expiry certificate",
            serial_number=latest_serial,
            issued_serial=serial_number,
            expires=latest_cert["Expires"]["S"],
        )

        assert_that(latest_cert).is_not_none()
        assert_that(latest_cert).contains_key("ExpiryReminders")

        expiry_reminders_first = latest_cert["ExpiryReminders"]["L"]
        log.info("ExpiryReminders after first invocation", reminders=expiry_reminders_first)
        assert_that(len(expiry_reminders_first)).is_greater_than_or_equal_to(1)

        # Step 5: Invoke the expiry reminder Lambda again
        log.info("invoking expiry lambda (second time)", function_name=expiry_function_name)
        invoke_lambda(expiry_function_name, {})

        # Step 6: Verify no new reminder was added
        latest_cert_2 = _find_latest_expiry_certificate(table_name, COMMON_NAME)
        latest_serial_2 = latest_cert_2["SerialNumber"]["S"]

        assert_that(latest_cert_2).is_not_none()
        assert_that(latest_cert_2).contains_key("ExpiryReminders")

        expiry_reminders_second = latest_cert_2["ExpiryReminders"]["L"]
        log.info("ExpiryReminders after second invocation", reminders=expiry_reminders_second)

        # Should still have the same number of reminders - no duplicate sent today
        assert_that(len(expiry_reminders_second)).is_equal_to(len(expiry_reminders_first))

    finally:
        # Restore tls.json to original state
        _restore_tls_json(bucket_name, kms_arn, original_tls_json)
        log.info("test cleanup complete")
