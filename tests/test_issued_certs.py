from assertpy import assert_that
import base64
from datetime import timedelta
from certvalidator.errors import InvalidCertificateError
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import DNSName, ExtensionOID, load_pem_x509_certificate
from utils.modules.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
    certificate_validated,
    convert_truststore,
)
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.aws.s3 import get_s3_bucket, put_s3_object, delete_s3_object


def test_cert_issued_no_passphrase():
    """
    Test certificate issued from a Certificate Signing Request with no passphrase
    """
    common_name = "pipeline-test-csr-no-passphrase.example.com"
    purposes = ["server_auth"]

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
        "purposes": purposes,
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
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check client auth extension is not present in certificate
    assert_that(certificate_validated).raises(InvalidCertificateError).when_called_with(
        cert_data, trust_roots, ["client_auth"]
    ).is_equal_to("The X.509 certificate provided is not valid for the purpose of client auth")


def test_client_cert_issued_only_includes_client_auth_extension():
    """
    Test client certificate issued only includes client authentication extension
    """
    common_name = "My test client"
    purposes = ["client_auth"]

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
        "purposes": purposes,
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

    # validate certificate including check for client auth extension
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check server auth extension is not present in certificate
    assert_that(certificate_validated).raises(InvalidCertificateError).when_called_with(
        cert_data, trust_roots, ["server_auth"]
    ).is_equal_to("The X.509 certificate provided is not valid for the purpose of server auth")


def test_cert_issued_with_passphrase():
    """
    Test certificate issued from a Certificate Signing Request with passphrase
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

    # validate certificate, check default setting is client auth
    assert_that(certificate_validated(cert_data, trust_roots, ["client_auth"])).is_true()

    # check server auth extension not present in certificate by default
    assert_that(certificate_validated).raises(InvalidCertificateError).when_called_with(
        cert_data, trust_roots, ["server_auth"]
    ).is_equal_to("The X.509 certificate provided is not valid for the purpose of server auth")


def test_issued_cert_includes_distinguished_name_specified_in_csr():
    """
    Test issued certification with no passphrase includes specified org and org unit from CSR
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
    purposes = ["client_auth", "server_auth"]

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
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
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


def test_issued_cert_includes_correct_dns_names():
    """
    Test issued certificate contains correct DNS names in Subject Alternative Name extension
    """
    common_name = "pipeline-test-dn-csr-no-passphrase.example.com"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"
    sans = ["test1.example.com", "test2.example.com", "invalid DNS name"]
    expected_result = ["test1.example.com", "test2.example.com"]
    purposes = ["server_auth"]

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
        "purposes": purposes,
        "sans": sans,
        "base64_csr_data": base64_csr_data,
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
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    sans_in_issued_cert = issued_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(DNSName)
    print(f"Issued certificate SubjectAlternativeName: {sans_in_issued_cert}")
    assert_that(sans_in_issued_cert).is_equal_to(expected_result)


def test_issued_cert_with_no_san_includes_correct_dns_name():
    """
    Test issued certificate with no SAN in CSR includes correct DNS name in Subject Alternative Name extension
    """
    common_name = "pipeline-test-common-name-in-san.example.com"
    country = "US"
    locality = "New York"
    organization = "Serverless Inc"
    organizational_unit = "DevOps"
    state = "New York"
    purposes = ["server_auth"]
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
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
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
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    sans_in_issued_cert = issued_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(DNSName)
    print(f"Issued certificate SubjectAlternativeName: {sans_in_issued_cert}")
    assert_that(sans_in_issued_cert).is_equal_to([common_name])


def test_cert_issued_without_san_if_common_name_invalid_dns():
    """
    Test certificate issued without SAN if common name not valid DNS and no SAN specified
    """
    common_name = "This is not a valid DNS name"
    country = "US"
    locality = "New York"
    organization = "Serverless Inc"
    organizational_unit = "DevOps"
    state = "New York"
    purposes = ["server_auth"]
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
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
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
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check client auth extension is not present in certificate
    assert_that(certificate_validated).raises(InvalidCertificateError).when_called_with(
        cert_data, trust_roots, ["client_auth"]
    ).is_equal_to("The X.509 certificate provided is not valid for the purpose of client auth")

    # check SAN extension not present in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    assert_that(issued_cert.extensions.get_extension_for_oid).raises(Exception).when_called_with(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).is_equal_to("No <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension was found")


def test_issued_cert_lifetime_as_expected():
    """
    Test issued certification with no passphrase has expected lifetime
    """
    common_name = "pipeline-test-cert-lifetime.example.com"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"
    purposes = ["client_auth", "server_auth"]

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
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
        "lifetime": 1,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # calculate issued certificate lifetime
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    issued_cert_lifetime = issued_cert.not_valid_after_utc - issued_cert.not_valid_before_utc
    print(f"Issued certificate lifetime: {issued_cert_lifetime}")

    # Expected cert lifetime is lifetime in days plus 5 minutes for clock skew
    expected_cert_lifetime = timedelta(days=json_data["lifetime"], minutes=5)
    print(f"Expected certificate lifetime: {expected_cert_lifetime}")

    # Assert that issued certificate lifetime is as expected
    assert_that(issued_cert_lifetime).is_equal_to(expected_cert_lifetime)


def test_max_cert_lifetime():
    """
    Test maximum certificate lifetime
    """
    common_name = "pipeline-test-max-cert-lifetime.example.com"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"
    purposes = ["client_auth"]

    max_cert_lifetime = 365

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
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
        "lifetime": 500,
        "force_issue": True,
        "cert_bundle": True,
    }

    print(f"Requested certificate lifetime: {json_data['lifetime']} days")

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # calculate issued certificate lifetime
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    issued_cert_lifetime = issued_cert.not_valid_after_utc - issued_cert.not_valid_before_utc
    print(f"Issued certificate lifetime: {issued_cert_lifetime}")

    # Expected cert lifetime is max cert lifetime in days plus 5 minutes for clock skew
    expected_cert_lifetime = timedelta(days=max_cert_lifetime, minutes=5)
    print(f"Expected certificate lifetime: {expected_cert_lifetime}")

    # Assert that issued certificate lifetime is as expected
    assert_that(issued_cert_lifetime).is_equal_to(expected_cert_lifetime)


def test_csr_uploaded_to_s3():
    """
    Test certificate issued from CSR uploaded to S3
    """
    common_name = "pipeline-test-csr-s3-upload"
    country = "GB"
    locality = "London"
    organization = "Acme Inc"
    organizational_unit = "Animation Department"
    state = "England"

    # Override certain values in CSR using JSON
    override_locality = "Override CSR Location"
    override_organization = "Override CSR Org"

    expected_subject = f"ST={state},OU={organizational_unit},O={override_organization},L={override_locality},C={country},CN={common_name}"

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Identify S3 bucket and KMS key for CSR upload
    bucket_name = get_s3_bucket()
    kms_arn = get_kms_details("-tls-keygen")[1]

    # Upload CSR to S3 bucket
    print(f"Uploading CSR to S3 bucket {bucket_name}")
    put_s3_object(bucket_name, kms_arn, f"csrs/{common_name}.csr", csr)

    # Construct JSON data to pass to Lambda function
    csr_file = f"{common_name}.csr"
    json_data = {
        "common_name": common_name,
        "lifetime": 1,
        "locality": override_locality,
        "organization": override_organization,
        "csr_file": csr_file,
        "force_issue": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # extract certificate from response including bundled certificate chain
    base64_cert_data = response["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data).decode("utf-8")

    # check subject of issued certificate with correct overrides
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    print(f"Issued certificate Subject: {issued_cert.subject.rfc4514_string()}")
    assert_that(issued_cert.subject.rfc4514_string()).is_equal_to(expected_subject)
