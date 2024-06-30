from .tls_cert import create_csr_info, create_csr_subject


def test_create_csr_info():
    event = {
        "common_name": "blah.example.com",
        "purposes": ["server_auth"],
    }

    csr_info = create_csr_info(event)
    assert csr_info.get_purposes() == ["server_auth"]


def test_create_csr_subject():
    event = {
        "common_name": "blah.example.com",
        "locality": "London",  # string, location
        "organization": "Acme Inc",  # string, organization name
        "organizational_unit": "Animation",  # string, organizational unit name
        "country": "GB",  # string, country code
    }

    subject = create_csr_subject(event)

    expected = "OU=Animation,O=Acme Inc,L=London,C=GB,CN=blah.example.com"
    assert subject.x509_name().rfc4514_string() == expected
