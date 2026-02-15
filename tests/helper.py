import base64
import structlog
from datetime import timedelta

from assertpy import assert_that
from typing import Optional, Union
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
    convert_pem_to_der,
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
    log.info("generating key pair using KMS key", kms_key_alias=key_alias, kms_key_arn=kms_arn)

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


def helper_invoke_tls_cert_lambda(json_data: dict[str, int | str]):
    function_name = get_lambda_name("-tls")
    log.info("invoking lambda function", function_name=function_name, json_data=json_data)
    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)
    log.info("lambda response", function_name=function_name, response=response)
    return response


def helper_fetch_certificate(json_data: dict[str, int | str], common_name: Optional[str] = None):
    response = helper_invoke_tls_cert_lambda(json_data)

    if common_name is not None:
        # Inspect the response which includes the signed certificate
        result = response["CertificateInfo"]["CommonName"]
        log.info("certificate issued", common_name=common_name)

        # Assert that the certificate was issued for the correct domain name
        assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    ca_chain = None
    if "Base64CaChain" in response:
        ca_chain = helper_ca_chain_der_from_response(response)

    return cert_data, ca_chain


def helper_generate_csr(csr_info: dict[str, str]):
    # Generate key pair using KMS key to ensure randomness
    private_key = helper_generate_kms_private_key("-tls-keygen", password=None)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    return csr


def _convert_ca_chain_pems(root_ca_pem, issuing_ca_pem, ca_chain_pem) -> (bytes, bytes, bytes):
    root_ca = convert_pem_to_der(root_ca_pem.encode("utf-8"))[0]
    issuing_ca = convert_pem_to_der(issuing_ca_pem.encode("utf-8"))[0]
    ca_chain = convert_pem_to_der(ca_chain_pem.encode("utf-8"))

    return root_ca, issuing_ca, ca_chain


def helper_fetch_ca_chain_der():
    root_ca_pem, issuing_ca_pem, ca_chain_pem = helper_fetch_ca_chain_pem()

    return _convert_ca_chain_pems(root_ca_pem, issuing_ca_pem, ca_chain_pem)


def helper_ca_chain_der_from_response(response):
    root_ca_pem, issuing_ca_pem, ca_chain_pem = helper_ca_chain_pem_from_response(response)

    root_ca, issuing_ca, ca_chain = _convert_ca_chain_pems(root_ca_pem, issuing_ca_pem, ca_chain_pem)

    return ca_chain


def helper_ca_chain_pem_from_response(response):
    assert "Base64IssuingCaCertificate" in response
    assert "Base64RootCaCertificate" in response
    assert "Base64CaChain" in response

    issuing_ca_certificate_b64 = response["Base64IssuingCaCertificate"]
    issuing_ca_certificate = base64.b64decode(issuing_ca_certificate_b64).decode("utf-8")

    root_ca_certificate_b64 = response["Base64IssuingCaCertificate"]
    root_ca_certificate = base64.b64decode(root_ca_certificate_b64).decode("utf-8")

    ca_chain_b64 = response["Base64CaChain"]
    ca_chain = base64.b64decode(ca_chain_b64).decode("utf-8")

    return root_ca_certificate, issuing_ca_certificate, ca_chain


def helper_fetch_ca_chain_pem():
    json_data = {
        "ca_chain_only": True,
    }

    response = helper_invoke_tls_cert_lambda(json_data)

    return helper_ca_chain_pem_from_response(response)


def construct_json_data(
    csr: bytes,
    common_name: str,
    purposes: Optional[list[str]] = None,
    extended_key_usages: Optional[list[str]] = None,
    passphrase: Optional[bool] = None,
    lifetime: int = 1,
    cert_bundle: bool = True,
    sans: Optional[Union[str, list, dict]] = None,
    override_locality: Optional[str] = None,
    override_organization: Optional[str] = None,
    csr_file: Optional[str] = None,
    ca_chain_only: Optional[bool] = None,
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

    if extended_key_usages is not None:
        json_data["extended_key_usages"] = extended_key_usages

    if passphrase is not None:
        json_data["passphrase"] = passphrase

    if override_locality:
        json_data["locality"] = override_locality

    if override_organization:
        json_data["organization"] = override_organization

    if csr_file:
        json_data["csr_file"] = csr_file

    if ca_chain_only is not None:
        json_data["ca_chain_only"] = ca_chain_only

    return json_data


def helper_get_certificate(
    csr_info: dict[str, str],
    purposes: Optional[list[str]] = None,
    extended_key_usages: Optional[list[str]] = None,
    passphrase: Optional[bool] = None,
    lifetime: int = 1,
    cert_bundle: bool = True,
    sans: Optional[Union[str, list, dict]] = None,
    override_locality: Optional[str] = None,
    override_organization: Optional[str] = None,
    csr_file: Optional[str] = None,
    ca_chain_only: Optional[bool] = None,
):
    common_name = csr_info["commonName"]

    csr = helper_generate_csr(csr_info)

    json_data = construct_json_data(
        csr,
        common_name,
        purposes=purposes,
        extended_key_usages=extended_key_usages,
        passphrase=passphrase,
        lifetime=lifetime,
        cert_bundle=cert_bundle,
        sans=sans,
        override_locality=override_locality,
        override_organization=override_organization,
        csr_file=csr_file,
        ca_chain_only=ca_chain_only,
    )

    return helper_fetch_certificate(json_data, common_name)
