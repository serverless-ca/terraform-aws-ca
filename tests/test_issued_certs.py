from assertpy import assert_that
import base64
import structlog
from datetime import timedelta
from certvalidator.errors import InvalidCertificateError

from cryptography.x509 import DNSName, load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend


from utils.modules.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
    certificate_validated,
    convert_truststore,
    convert_pem_to_der,
)

from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.aws.s3 import get_s3_bucket, put_s3_object
from .helper import (
    helper_create_csr_info,
    helper_get_certificate,
    helper_generate_csr,
    helper_invoke_tls_cert_lambda,
    helper_fetch_certificate,
    helper_generate_kms_private_key,
    helper_assert_expected_lifetime,
    helper_fetch_ca_chain_der,
    helper_fetch_ca_chain_pem,
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

log = structlog.get_logger(__name__)


def test_cert_issued_no_passphrase():
    """
    Test certificate issued from a Certificate Signing Request with no passphrase
    """
    common_name = "pipeline-test-csr-no-passphrase.example.com"
    purposes = ["server_auth"]

    csr_info = create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes, passphrase=False)

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

    csr_info = create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes, passphrase=False)

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

    csr_info = create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=None, passphrase=None)

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

    csr_info = helper_create_csr_info(common_name)

    expected_subject = f'ST={csr_info["state"]},OU={csr_info["organizationalUnit"]},O={csr_info["organization"]},L={csr_info["locality"]},C={csr_info["country"]},CN={csr_info["commonName"]}'
    purposes = ["client_auth", "server_auth"]

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes)

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots)).is_true()

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    assert_that(issued_cert.subject.rfc4514_string()).is_equal_to(expected_subject)


def test_issued_cert_includes_correct_dns_names():
    """
    Test issued certificate contains correct DNS names in Subject Alternative Name extension
    """
    common_name = "pipeline-test-dn-csr-no-passphrase.example.com"
    sans = ["test1.example.com", "test2.example.com", "invalid DNS name"]
    expected_result = ["test1.example.com", "test2.example.com"]

    purposes = ["server_auth"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, sans=sans)

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    sans_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans_in_issued_cert = sans_extension.value.get_values_for_type(DNSName)
    log.info("issued certificate", subject_alternative_names=sans_in_issued_cert)

    assert_that(sans_in_issued_cert).is_equal_to(expected_result)


def test_issued_cert_with_no_san_includes_correct_dns_name():
    """
    Test issued certificate with no SAN in CSR includes correct DNS name in Subject Alternative Name extension
    """
    common_name = "pipeline-test-common-name-in-san.example.com"
    purposes = ["server_auth"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes)

    # convert bundle to trust store format
    trust_roots = convert_truststore(cert_data)

    # validate certificate
    assert_that(certificate_validated(cert_data, trust_roots, purposes)).is_true()

    # check subject of issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    sans_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans_in_issued_cert = sans_extension.value.get_values_for_type(DNSName)
    log.info("issued_certificate", subject_alternative_names=sans_in_issued_cert)

    assert_that(sans_in_issued_cert).is_equal_to([common_name])


def test_cert_issued_without_san_if_common_name_invalid_dns():
    """
    Test certificate issued without SAN if common name not valid DNS and no SAN specified
    """
    common_name = "This is not a valid DNS name"
    purposes = ["server_auth"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes)

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
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    assert_that(issued_cert.extensions.get_extension_for_oid).raises(Exception).when_called_with(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).is_equal_to("No <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension was found")


def test_issued_cert_lifetime_as_expected():
    """
    Test issued certification with no passphrase has expected lifetime
    """
    common_name = "pipeline-test-cert-lifetime.example.com"

    purposes = ["client_auth", "server_auth"]
    lifetime = 1

    # Expected cert lifetime is lifetime in days plus 5 minutes for clock skew
    expected_cert_lifetime = timedelta(days=lifetime, minutes=5)
    log.info("expected certificate lifetime", lifetime=expected_cert_lifetime)

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, lifetime=lifetime)

    helper_assert_expected_lifetime(cert_data, expected_cert_lifetime)


def test_max_cert_lifetime():
    """
    Test maximum certificate lifetime
    """
    common_name = "pipeline-test-max-cert-lifetime.example.com"
    purposes = ["client_auth"]

    max_cert_lifetime = 365  # need to fix this magic number
    expected_cert_lifetime = timedelta(days=max_cert_lifetime, minutes=5)
    log.info("expected certificate lifetime", lifetime=expected_cert_lifetime)

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, lifetime=500)

    helper_assert_expected_lifetime(cert_data, expected_cert_lifetime)


def test_csr_uploaded_to_s3():
    """
    Test certificate issued from CSR uploaded to S3
    """
    common_name = "pipeline-test-csr-s3-upload"

    csr_info = helper_create_csr_info(common_name)

    # Override certain values in CSR using JSON
    override_locality = "Override CSR Location"
    override_organization = "Override CSR Org"

    expected_subject = f'ST={csr_info["state"]},OU={csr_info["organizationalUnit"]},O={override_organization},L={override_locality},C={csr_info["country"]},CN={csr_info["commonName"]}'

    # Generate key pair using KMS key to ensure randomness
    private_key = helper_generate_kms_private_key("-tls-keygen", password=None)

    # Generate Certificate Signing Request
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Identify S3 bucket and KMS key for CSR upload
    bucket_name = get_s3_bucket()
    kms_arn = get_kms_details("-tls-keygen")[1]

    # Upload CSR to S3 bucket
    put_s3_object(bucket_name, kms_arn, f"csrs/{common_name}.csr", csr)

    # Construct JSON data to pass to Lambda function
    csr_file = f"{common_name}.csr"
    json_data = {
        "common_name": common_name,
        "lifetime": 1,
        "locality": override_locality,
        "organization": override_organization,
        "csr_file": csr_file,
    }

    cert_data, ca_chain = helper_fetch_certificate(json_data)

    # check subject of issued certificate with correct overrides
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    assert_that(issued_cert.subject.rfc4514_string()).is_equal_to(expected_subject)


def test_no_private_key_reuse():
    """
    Test certificate request rejected if private key has already been used for a certificate
    """
    common_name = "pipeline-test-private-key-reuse.example.com"
    purposes = ["server_auth"]

    csr_info = helper_create_csr_info(common_name)

    csr = helper_generate_csr(csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "purposes": purposes,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
        "cert_bundle": True,
    }

    # Invoke TLS certificate Lambda function
    response = helper_invoke_tls_cert_lambda(json_data)

    # Inspect the response which includes the signed certificate
    issued_common_name = response["CertificateInfo"]["CommonName"]
    log.info("certificate issued", common_name=issued_common_name)
    assert_that(issued_common_name).is_equal_to(common_name)

    # Check 2nd request using same private key is rejected
    response_2 = helper_invoke_tls_cert_lambda(json_data)
    assert_that(response_2["error"]).is_equal_to("Private key has already been used for a certificate")

    # Check override works
    json_data["force_issue"] = True

    # Invoke TLS certificate Lambda function
    response_3 = helper_invoke_tls_cert_lambda(json_data)

    # Inspect the response which includes the signed certificate
    issued_common_name = response_3["CertificateInfo"]["CommonName"]
    log.info("certificate issued", common_name=issued_common_name)
    assert_that(issued_common_name).is_equal_to(common_name)


def test_ca_chain_only():
    # generate certificate
    common_name = "test-ca-chain-only.example.com"
    csr_info = helper_create_csr_info(common_name)
    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=["server_auth"])

    # fetch ca chain
    root_ca_der, issuing_ca_der, ca_chain_der = helper_fetch_ca_chain_der()

    # confirm chain validates generated certificate
    assert_that(certificate_validated(cert_data, ca_chain_der, purposes=["server_auth"])).is_true()


def test_cas_end_with_new_line():
    root_ca_certificate, issuing_ca_certificate, ca_chain = helper_fetch_ca_chain_pem()

    assert root_ca_certificate.endswith("\n")
    assert issuing_ca_certificate.endswith("\n")
    assert ca_chain.endswith("\n")
    

def _test_include_ca_chain(cert_bundle=None):
    # generate certificate
    common_name = "include-ca-chain.example.com"
    csr_info = helper_create_csr_info(common_name)
    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=["server_auth"], cert_bundle=cert_bundle)

    cert_der = convert_pem_to_der(cert_data.encode("utf-8"))

    # confirm chain validates generated certificate
    assert_that(certificate_validated(cert_data, ca_chain, purposes=["server_auth"])).is_true()


def test_include_ca_chain_no_cert_bundle():
    return _test_include_ca_chain(cert_bundle=False)


def test_include_ca_chain_with_cert_bundle():
    return _test_include_ca_chain(cert_bundle=True)
