from lambda_code.tls_cert.tls_cert import (
    create_csr_info,
    create_csr_subject,
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
