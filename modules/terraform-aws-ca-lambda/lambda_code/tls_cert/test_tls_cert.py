# TODO:  need to figure out how to get rid of this grossness
if __package__ is None:
    from tls_cert import create_csr_info, create_csr_subject
else:
    from .tls_cert import create_csr_info, create_csr_subject


def test_create_csr_info():
    event = {
        "common_name": "blah.example.com",
    }

    csr_info = create_csr_info(event)
    assert csr_info.purposes == ["client_auth"]
    assert csr_info.sans == ["blah.example.com"]


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
