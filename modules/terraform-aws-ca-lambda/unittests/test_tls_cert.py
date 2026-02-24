from lambda_code.tls_cert.tls_cert import (
    certificate_already_issued,
    create_csr_info,
    create_csr_subject,
    CaChainResponse,
    CertificateResponse,
    Request,
)
from utils.certs.types import Subject
from unittest.mock import patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
from dateutil.tz import tzutc
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_csr(private_key, common_name="test.example.com"):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )


def _generate_test_cert(private_key, common_name="test.example.com", not_valid_before=None):
    if not_valid_before is None:
        not_valid_before = datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_before + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert


def _make_db_certificate(cert):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }


def test_create_csr_info():
    event = {
        "common_name": "blah.example.com",
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["client_auth"]
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "blah.example.com"}]


def test_create_csr_info_with_purpose_and_sans():
    event = {
        "common_name": "blah.example.com",
        "purposes": ["server_auth"],
        "sans": ["a.b.d.com"],
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["server_auth"]
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "a.b.d.com"}]


def test_create_csr_info_with_purpose_no_sans():
    event = {
        "common_name": "blah.example.com",
        "purposes": ["server_auth"],
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["server_auth"]
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "blah.example.com"}]
    assert csr_info.subject.common_name == "blah.example.com"


def test_create_csr_info_with_typed_sans():
    """Test SANs with multiple types using list of dicts format"""
    event = {
        "common_name": "test.example.com",
        "sans": [
            {"type": "DNS_NAME", "value": "www.example.com"},
            {"type": "IP_ADDRESS", "value": "192.168.1.1"},
            {"type": "EMAIL_ADDRESS", "value": "admin@example.com"},
        ],
    }

    csr_info = create_csr_info(event)
    assert len(csr_info.sans) == 3
    assert {"type": "DNS_NAME", "value": "www.example.com"} in csr_info.sans
    assert {"type": "IP_ADDRESS", "value": "192.168.1.1"} in csr_info.sans
    assert {"type": "EMAIL_ADDRESS", "value": "admin@example.com"} in csr_info.sans


def test_create_csr_info_with_sans_map_format():
    """Test SANs using map format"""
    event = {
        "common_name": "test.example.com",
        "sans": {
            "DNS_NAME": ["www.example.com", "api.example.com"],
            "IP_ADDRESS": "10.0.0.1",
        },
    }

    csr_info = create_csr_info(event)
    assert len(csr_info.sans) == 3
    assert {"type": "DNS_NAME", "value": "www.example.com"} in csr_info.sans
    assert {"type": "DNS_NAME", "value": "api.example.com"} in csr_info.sans
    assert {"type": "IP_ADDRESS", "value": "10.0.0.1"} in csr_info.sans


def test_create_csr_info_with_single_string_san():
    """Test backwards compatibility with single string SAN"""
    event = {
        "common_name": "test.example.com",
        "sans": "www.example.com",
    }

    csr_info = create_csr_info(event)
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "www.example.com"}]


def test_create_csr_info_invalid_san_excluded():
    """Test that invalid SANs are excluded"""
    event = {
        "common_name": "test.example.com",
        "sans": [
            {"type": "DNS_NAME", "value": "valid.example.com"},
            {"type": "IP_ADDRESS", "value": "not-an-ip"},
            {"type": "EMAIL_ADDRESS", "value": "not-an-email"},
        ],
    }

    csr_info = create_csr_info(event)
    # Only the valid DNS_NAME should be included
    assert len(csr_info.sans) == 1
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "valid.example.com"}]


def test_create_csr_subject():
    event = {
        "common_name": "blah.example.com",
        "locality": "London",  # string, location
        "organization": "Acme Inc",  # string, organization name
        "organizational_unit": "Animation",  # string, organizational unit name
        "state": "England",
        "email_address": "test@example.com",
        "country": "GB",  # string, country code
    }

    subject = create_csr_subject(event)

    expected = (
        "ST=England,OU=Animation,O=Acme Inc,L=London,1.2.840.113549.1.9.1=test@example.com,C=GB,CN=blah.example.com"
    )
    assert subject.x509_name().rfc4514_string() == expected


def test_request_deserialise_basic():
    event = {"common_name": "test.example.com"}

    request = Request.from_dict(event)

    assert request.common_name == "test.example.com"
    assert request.lifetime == 30


def test_request_deserialise_full():
    event = {
        "common_name": "test.example.com",
        "locality": "London",
        "organization": "Example",
        "organizational_unit": "IT",
        "country": "GB",
        "email_address": "blah@example.com",
        "state": "London",
        "lifetime": 365,
        "purposes": ["server_auth"],
        "sans": ["test2.example.com"],
        "ca_chain_only": True,
        "force_issue": True,
        "csr_file": "csr.pem",
        "cert_bundle": True,
        "base64_csr_data": "base64data",
    }

    request = Request(**event)

    assert request.common_name == "test.example.com"
    assert request.lifetime == 365
    assert request.purposes == ["server_auth"]
    assert request.csr_file == "csr.pem"


def test_response_serialise_as_dict():
    response = CertificateResponse(
        certificate_info={
            "CommonName": "test.example.com",
            "SerialNumber": "123456",
            "Issued": "2021-01-01 00:00:00",
            "Expires": "2022-01-01 00:00:00",
        },
        base64_certificate="base64data",
        subject="test.example.com",
        base64_issuing_ca_certificate="base64data",
        base64_root_ca_certificate="base64data",
        base64_ca_chain="base64data",
    )

    serialised = response.to_dict()

    assert serialised == {
        "CertificateInfo": {
            "CommonName": "test.example.com",
            "SerialNumber": "123456",
            "Issued": "2021-01-01 00:00:00",
            "Expires": "2022-01-01 00:00:00",
        },
        "Base64Certificate": "base64data",
        "Subject": "test.example.com",
        "Base64IssuingCaCertificate": "base64data",
        "Base64RootCaCertificate": "base64data",
        "Base64CaChain": "base64data",
    }


def test_ca_chain_response_serialise_as_dict():
    response = CaChainResponse(
        base64_issuing_ca_certificate="base64data",
        base64_root_ca_certificate="base64data",
        base64_ca_chain="base64data",
    )

    serialised = response.to_dict()

    assert serialised == {
        "Base64IssuingCaCertificate": "base64data",
        "Base64RootCaCertificate": "base64data",
        "Base64CaChain": "base64data",
    }


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_matching(mock_db_list):
    """Test returns True when CSR matches an existing certificate"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    cert = _generate_test_cert(private_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is True


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_force_issue(mock_db_list):
    """Test returns False when force_issue is True"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", True)
    assert result is False
    mock_db_list.assert_not_called()


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_last_modified_none(mock_db_list):
    """Test returns False when last_modified is None"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")

    result = certificate_already_issued(csr, subject, None, "test-project", "dev", False)
    assert result is False
    mock_db_list.assert_not_called()


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_no_certificates(mock_db_list):
    """Test returns False when no certificates exist in DynamoDB"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    mock_db_list.return_value = []

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_different_key(mock_db_list):
    """Test returns False when public key does not match"""
    csr_key = _generate_test_key()
    cert_key = _generate_test_key()
    csr = _generate_test_csr(csr_key)
    cert = _generate_test_cert(cert_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_different_date(mock_db_list):
    """Test returns False when last_modified date does not match certificate valid_from date"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    cert = _generate_test_cert(private_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    # last_modified is a different day
    last_modified = datetime(2025, 12, 1, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_different_subject(mock_db_list):
    """Test returns False when CSR subject does not match certificate subject"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key, common_name="other.example.com")
    cert = _generate_test_cert(private_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("other.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False
