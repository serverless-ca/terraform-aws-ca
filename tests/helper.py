import base64
import structlog
from datetime import timedelta

from assertpy import assert_that
from typing import Optional
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
)

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


def helper_generate_kms_private_key(key_purpose: str, password: Optional[str] = None):
    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details(key_purpose)
    log.debug("generating key pair using KMS key", kms_key_alias=key_alias, kms_key_arn=kms_arn)

    # Generate key pair using KMS key to ensure randomness
    return load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], password=password)


def helper_create_csr_info(
    common_name: str,
    country: str = "US",
    locality: str = "New York",
    organization: str = "Serverless Inc",
    organizational_unit: str = "DevOps",
    state: str = "New York",
) -> dict[str, str]:
    return create_csr_info(common_name, country, locality, organization, organizational_unit, state)


def helper_assert_expected_lifetime(cert_data: str, expected_lifetime: timedelta):
    # calculate issued certificate lifetime
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())

    issued_cert_lifetime = issued_cert.not_valid_after_utc - issued_cert.not_valid_before_utc

    # Assert that issued certificate lifetime is as expected
    assert_that(issued_cert_lifetime).is_equal_to(expected_lifetime)


def helper_invoke_cert_lambda(json_data: dict[str, int | str], common_name: Optional[str] = None):
    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    log.debug("invoking lambda function", function_name=function_name)
    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    if common_name is not None:
        # Inspect the response which includes the signed certificate
        result = response["CertificateInfo"]["CommonName"]
        log.debug("certificate issued", common_name=common_name)

        # Assert that the certificate was issued for the correct domain name
        assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    return cert_data


def helper_generate_csr(csr_info: dict[str, str]):
    # Generate key pair using KMS key to ensure randomness
    private_key = helper_generate_kms_private_key("-tls-keygen", password=None)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    return csr


def construct_json_data(
    csr: bytes,
    common_name: str,
    purposes: Optional[list[str]] = None,
    passphrase: Optional[bool] = None,
    lifetime: int = 1,
    cert_bundle: bool = True,
    sans: Optional[list[str]] = None,
    override_locality: Optional[str] = None,
    override_organization: Optional[str] = None,
    csr_file: Optional[str] = None,
):
    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "lifetime": lifetime,
        "cert_bundle": cert_bundle,
    }

    if sans is not None:
        json_data["sans"] = sans

    if purposes is not None:
        json_data["purposes"] = purposes

    if passphrase is not None:
        json_data["passphrase"] = passphrase

    if override_locality:
        json_data["locality"] = override_locality

    if override_organization:
        json_data["organization"] = override_organization

    if csr_file:
        json_data["csr_file"] = csr_file

    return json_data


def helper_get_certificate(
    csr_info: dict[str, str],
    purposes: Optional[list[str]] = None,
    passphrase: Optional[bool] = None,
    lifetime: int = 1,
    cert_bundle: bool = True,
    sans: Optional[list[str]] = None,
    override_locality: Optional[str] = None,
    override_organization: Optional[str] = None,
    csr_file: Optional[str] = None,
):
    common_name = csr_info["commonName"]

    csr = helper_generate_csr(csr_info)

    json_data = construct_json_data(
        csr,
        common_name,
        purposes=purposes,
        passphrase=passphrase,
        lifetime=lifetime,
        cert_bundle=cert_bundle,
        sans=sans,
        override_locality=override_locality,
        override_organization=override_organization,
        csr_file=csr_file,
    )

    return helper_invoke_cert_lambda(json_data, common_name)
