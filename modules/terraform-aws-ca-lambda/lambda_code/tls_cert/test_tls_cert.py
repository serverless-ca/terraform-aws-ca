from .tls_cert import (
    create_csr_info,
    create_csr_subject,
    CaChainResponse,
    CertificateResponse,
    Request,
    base64_decode_bytes_to_str,
    base64_encode_bytes_to_str,
)


def test_create_csr_info():
    event = {
        "common_name": "blah.example.com",
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["client_auth"]
    assert csr_info.sans == ["blah.example.com"]


def test_base64_decode_bytes_to_str():
    assert base64_decode_bytes_to_str(b"Zm9v") == "foo"


def test_base64_encode_bytes_to_str():
    assert base64_encode_bytes_to_str(b"foo") == "Zm9v"


def test_create_csr_info_with_purpose_and_sans():
    event = {
        "common_name": "blah.example.com",
        "purposes": ["server_auth"],
        "sans": ["a.b.d.com"],
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["server_auth"]
    assert csr_info.sans == ["a.b.d.com"]


def test_create_csr_info_with_purpose_no_sans():
    event = {
        "common_name": "blah.example.com",
        "purposes": ["server_auth"],
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["server_auth"]
    assert csr_info.sans == ["blah.example.com"]
    assert csr_info.subject.common_name == "blah.example.com"


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
