from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import NameOID

from lambda_code.tls_cert.tls_cert import (
    create_csr_info,
    create_csr_subject,
    sns_notify_csr_rejected,
    CaChainResponse,
    CertificateResponse,
    Request,
)


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


def _generate_csr(common_name, organization=None):
    """Helper to generate a CSR with a given subject"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject_attrs = [crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        subject_attrs.append(crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    csr = (
        crypto_x509.CertificateSigningRequestBuilder()
        .subject_name(crypto_x509.Name(subject_attrs))
        .sign(private_key, hashes.SHA256())
    )
    return csr


@patch("lambda_code.tls_cert.tls_cert.publish_to_sns")
def test_sns_notify_csr_rejected_uses_csr_info_subject(mock_publish):
    """Test that rejection notification Subject comes from csr_info, not from raw CSR"""
    mock_publish.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    # CSR with a different subject than csr_info
    csr = _generate_csr("csr-embedded.example.com", organization="CSR Org")

    # csr_info with the intended (overridden) subject
    event = {
        "common_name": "intended-override.example.com",
        "organization": "Override Org",
        "lifetime": 30,
    }
    csr_info = create_csr_info(event)

    sns_notify_csr_rejected(csr_info, csr, "Private key has already been used for a certificate", "arn:aws:sns:test")

    call_args = mock_publish.call_args
    rejection_data = call_args[0][0]

    # Subject must come from csr_info, not the raw CSR
    assert "CN=intended-override.example.com" in rejection_data["Subject"]
    assert "O=Override Org" in rejection_data["Subject"]
    assert "csr-embedded.example.com" not in rejection_data["Subject"]
    assert "CSR Org" not in rejection_data["Subject"]

    # CSRInfo fields should also reflect csr_info
    assert rejection_data["CSRInfo"]["CommonName"] == "intended-override.example.com"


@patch("lambda_code.tls_cert.tls_cert.publish_to_sns")
def test_sns_notify_csr_rejected_subject_matches_csr_info_rfc4514(mock_publish):
    """Test that rejection Subject matches the RFC 4514 format from csr_info subject"""
    mock_publish.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    csr = _generate_csr("different.example.com")

    event = {
        "common_name": "test.example.com",
        "organization": "Test Org",
        "country": "GB",
        "locality": "London",
        "lifetime": 90,
    }
    csr_info = create_csr_info(event)
    expected_subject = csr_info.subject.x509_name().rfc4514_string()

    sns_notify_csr_rejected(csr_info, csr, "Private key has already been used for a certificate", "arn:aws:sns:test")

    call_args = mock_publish.call_args
    rejection_data = call_args[0][0]

    assert rejection_data["Subject"] == expected_subject
