from assertpy import assert_that
from tests.utils_tests.aws.lambdas import get_lambda_name, invoke_lambda


def test_tls_cert_no_csr_fails():
    """
    Test TLS certificate with no CSR fails
    """
    common_name = "pipeline-test-no-csr-no-passphrase.example.com"

    # Construct JSON data to pass to Lambda function
    json_data = {
        "common_name": common_name,
        "lifetime": 1,
        "passphrase": False,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    assert_that("Base64Certificate").is_not_in(response)
    assert_that(response["error"]).is_equal_to("Private key storage in DynamoDB disabled")
