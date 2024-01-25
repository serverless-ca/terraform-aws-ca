from assertpy import assert_that
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, NameOID
from tests.utils_tests.certs.crypto import (
    certificate_validated,
    convert_truststore,
)
from tests.utils_tests.aws.lambdas import get_lambda_name, invoke_lambda


def test_tls_cert_issued_no_csr_no_passphrase():
    """
    Test TLS certificate with no Certificate Signing Request and no passphrase
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

    # Inspect the response which includes the signed certificate
    result = response["CertificateInfo"]["CommonName"]
    print(f"Certificate issued for {common_name}")

    # Assert that the certificate was issued for the correct domain name
    assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots)).is_true()


def test_tls_cert_issued_no_csr_passphrase():
    """
    Test TLS certificate with no Certificate Signing Request with passphrase
    """
    common_name = "pipeline-test-no-csr-passphrase.example.com"

    # Construct JSON data to pass to Lambda function
    json_data = {
        "common_name": common_name,
        "lifetime": 1,
        "passphrase": True,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # Inspect the response which includes the signed certificate
    result = response["CertificateInfo"]["CommonName"]
    print(f"Certificate issued for {common_name}")

    # Assert that the certificate was issued for the correct domain name
    assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots)).is_true()


def test_tls_cert_issued_no_csr_with_specified_ou():
    """
    Test TLS certificate with passphrase but no CSR includes org and org unit if specified
    """
    common_name = "pipeline-test-ou-no-csr-passphrase.example.com"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"

    # Construct JSON data to pass to Lambda function
    json_data = {
        "common_name": common_name,
        "organization": organization,
        "organizational_unit": organizational_unit,
        "lifetime": 1,
        "passphrase": True,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # Inspect the response which includes the signed certificate
    result = response["CertificateInfo"]["CommonName"]
    print(f"Certificate issued for {common_name}")

    # Assert that the certificate was issued for the correct domain name
    assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots)).is_true()

    # check org and org unit of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    issued_cert_organization = issued_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    print(f"Issued certificate Organization: {issued_cert_organization}")
    issued_cert_organizational_unit = issued_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[
        0
    ].value
    print(f"Issued certificate Organizational Unit: {issued_cert_organizational_unit}")
    assert_that(issued_cert_organization).is_equal_to(organization)
    assert_that(issued_cert_organizational_unit).is_equal_to(organizational_unit)


def test_tls_cert_issued_no_csr_includes_issuing_ca_org_by_default():
    """
    Test TLS certificate with passphrase but no CSR includes same org as Issuing CA by default
    """
    common_name = "pipeline-test-o-no-csr-passphrase.example.com"

    # Construct JSON data to pass to Lambda function
    json_data = {
        "common_name": common_name,
        "lifetime": 1,
        "passphrase": True,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # Inspect the response which includes the signed certificate
    result = response["CertificateInfo"]["CommonName"]
    print(f"Certificate issued for {common_name}")

    # Assert that the certificate was issued for the correct domain name
    assert_that(result).is_equal_to(common_name)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots)).is_true()

    # check organization of issued certificate matches issuing ca organization
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issuer: {issued_cert.issuer.rfc4514_string()}")
    issuer_organization = issued_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    issued_cert_organization = issued_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    assert_that(issued_cert_organization).is_equal_to(issuer_organization)
