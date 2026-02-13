from assertpy import assert_that
import base64
import json
import structlog
from datetime import timedelta
from certvalidator.errors import InvalidCertificateError

from cryptography.x509 import DNSName, load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend


from utils.modules.certs.crypto import (
    crypto_tls_cert_signing_request,
    create_csr_info,
    certificate_validated,
    convert_truststore,
    convert_pem_to_der,
)

from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.s3 import delete_s3_object, get_s3_bucket, list_s3_object_keys, put_s3_object
from .helper import (
    helper_create_csr_info,
    helper_get_certificate,
    helper_generate_csr,
    helper_invoke_tls_cert_lambda,
    helper_fetch_certificate,
    helper_generate_kms_private_key,
    helper_assert_expected_lifetime,
    helper_fetch_ca_chain_der,
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
    sans = ["test1.example.com", "test2.example.com", "*.example.com", "*.com", "invalid DNS name"]
    expected_result = ["test1.example.com", "test2.example.com", "*.example.com"]

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

    # If no tls.json present, test for SNS notification
    test_sns = False
    if "tls.json" not in list_s3_object_keys(bucket_name):
        test_sns = True
        certs_json = [{"common_name": common_name, "lifetime": 1, "csr_file": f"{common_name}.csr"}]
        tls_file = bytes(json.dumps(certs_json), "utf-8")
        put_s3_object(bucket_name, kms_arn, "tls.json", tls_file)

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
    if test_sns:
        # check SNS messsage received via email subscription
        # TODO: implement programatically within tests
        delete_s3_object(bucket_name, "tls.json")


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


def test_extended_key_usage_code_signing():
    """
    Test certificate issued with CODE_SIGNING extended key usage
    """
    common_name = "pipeline-test-eku-code-signing"
    purposes = ["client_auth"]
    extended_key_usages = ["CODE_SIGNING"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, extended_key_usages=extended_key_usages)

    # check extended key usage extension in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    eku_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = list(eku_extension.value)

    log.info("extended key usages", eku_oids=[str(oid) for oid in eku_oids])

    # Assert CODE_SIGNING OID is present
    assert_that(ExtendedKeyUsageOID.CODE_SIGNING in eku_oids).is_true()
    # Assert CLIENT_AUTH OID is present (from purposes)
    assert_that(ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids).is_true()


def test_extended_key_usage_multiple():
    """
    Test certificate issued with multiple extended key usages
    """
    common_name = "pipeline-test-eku-multiple"
    purposes = ["client_auth"]
    extended_key_usages = ["CODE_SIGNING", "EMAIL_PROTECTION", "TIME_STAMPING"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, extended_key_usages=extended_key_usages)

    # check extended key usage extension in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    eku_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = list(eku_extension.value)

    log.info("extended key usages", eku_oids=[str(oid) for oid in eku_oids])

    # Assert all expected OIDs are present
    assert_that(ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids).is_true()
    assert_that(ExtendedKeyUsageOID.CODE_SIGNING in eku_oids).is_true()
    assert_that(ExtendedKeyUsageOID.EMAIL_PROTECTION in eku_oids).is_true()
    assert_that(ExtendedKeyUsageOID.TIME_STAMPING in eku_oids).is_true()

    # Assert total count is 4 (client_auth + 3 extended key usages)
    assert_that(len(eku_oids)).is_equal_to(4)


def test_extended_key_usage_with_custom_oid():
    """
    Test certificate issued with a custom OID extended key usage
    """
    common_name = "pipeline-test-eku-custom-oid"
    purposes = ["client_auth"]
    # IPSEC_END_SYSTEM OID specified as string
    custom_oid = "1.3.6.1.5.5.7.3.5"
    extended_key_usages = [custom_oid]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, extended_key_usages=extended_key_usages)

    # check extended key usage extension in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    eku_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = list(eku_extension.value)

    log.info("extended key usages", eku_oids=[str(oid) for oid in eku_oids])

    # Assert custom OID is present by checking dotted string representation
    oid_strings = [oid.dotted_string for oid in eku_oids]
    assert_that(custom_oid in oid_strings).is_true()

    # Assert CLIENT_AUTH is also present
    assert_that(ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids).is_true()


def test_extended_key_usage_no_duplicates():
    """
    Test that duplicate extended key usages are not added to certificate
    """
    common_name = "pipeline-test-eku-no-duplicates"
    # Request client_auth in both purposes and extended_key_usages
    purposes = ["client_auth"]
    extended_key_usages = ["TLS_WEB_CLIENT_AUTHENTICATION"]

    csr_info = helper_create_csr_info(common_name)

    cert_data, ca_chain = helper_get_certificate(csr_info, purposes=purposes, extended_key_usages=extended_key_usages)

    # check extended key usage extension in issued certificate
    issued_cert = load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
    log.info("issued certificate", subject=issued_cert.subject.rfc4514_string())

    eku_extension = issued_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    eku_oids = list(eku_extension.value)

    log.info("extended key usages", eku_oids=[str(oid) for oid in eku_oids])

    # Assert only one CLIENT_AUTH OID is present (no duplicates)
    client_auth_count = sum(1 for oid in eku_oids if oid == ExtendedKeyUsageOID.CLIENT_AUTH)
    assert_that(client_auth_count).is_equal_to(1)
    assert_that(len(eku_oids)).is_equal_to(1)
