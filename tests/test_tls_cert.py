from assertpy import assert_that
import base64
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import DNSName, ExtensionOID, load_pem_x509_certificate, load_pem_x509_csr
from tests.utils_tests.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
    certificate_validated,
    convert_truststore,
)
from tests.utils_tests.certs.kms import kms_generate_key_pair
from tests.utils_tests.aws.kms import get_kms_details
from tests.utils_tests.aws.lambdas import get_lambda_name, invoke_lambda


def test_tls_cert_issued_csr_no_passphrase():
    """
    Test TLS certificate issued from a Certificate Signing Request with no passphrase
    """
    common_name = "pipeline-test-csr-no-passphrase.example.com"

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
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


def test_tls_cert_issued_csr_passphrase():
    """
    Test TLS certificate issued from a Certificate Signing Request with passphrase
    """
    common_name = "pipeline-test-csr-passphrase.example.com"

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    # Generate Certificate Signing Request
    csr_info = create_csr_info(common_name)
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": True,
        "lifetime": 1,
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


def test_tls_cert_issued_csr_includes_specified_distinguished_name():
    """
    Test TLS certificate issued with specified org and org unit from CSR with no passphrase
    """
    common_name = "pipeline-test-dn-csr-no-passphrase.example.com"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"
    expected_subject = (
        "ST=England,OU=Animation Department,O=Acme Inc,L=London,C=GB,CN=pipeline-test-dn-csr-no-passphrase.example.com"
    )

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
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

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    assert_that(issued_cert.subject.rfc4514_string()).is_equal_to(expected_subject)


def test_tls_cert_issued_csr_includes_correct_dns_names():
    """
    Test TLS certificate issued contains correct DNS names in Subject Alternative Name extension
    """
    common_name = "pipeline-test-dn-csr-no-passphrase.example.com"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"
    sans = ["test1.example.com", "test2.example.com", "invalid DNS name"]
    expected_result = ["test1.example.com", "test2.example.com"]

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "sans": sans,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
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

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    sans_in_issued_cert = issued_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(DNSName)
    print(f"Issued certificate SubjectAlternativeName: {sans_in_issued_cert}")
    assert_that(sans_in_issued_cert).is_equal_to(expected_result)


def test_tls_cert_issued_csr_with_no_san_includes_correct_dns_name():
    """
    Test TLS certificate with no SAN in CSR includes correct DNS name in Subject Alternative Name extension
    """
    common_name = "pipeline-test-common-name-in-san.example.com"
    country = "US"
    locality = "New York"
    organization = "Serverless Inc"
    organizational_unit = "DevOps"
    state = "New York"
    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
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

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    sans_in_issued_cert = issued_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(DNSName)
    print(f"Issued certificate SubjectAlternativeName: {sans_in_issued_cert}")
    assert_that(sans_in_issued_cert).is_equal_to([common_name])


def test_tls_cert_issued_without_san_if_common_name_invalid_dns():
    """
    Test TLS certificate issued without SAN if common name not valid DNS and no SAN specified
    """
    common_name = "This is not a valid DNS name"
    country = "US"
    locality = "New York"
    organization = "Serverless Inc"
    organizational_unit = "DevOps"
    state = "New York"
    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
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

    # check SAN extension not present in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    assert_that(issued_cert.extensions.get_extension_for_oid).raises(Exception).when_called_with(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).is_equal_to("No <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension was found")
