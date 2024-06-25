from .tls_cert import create_csr_info, create_csr_subject


def test_create_csr_info():
    event = {
        "common_name": ["blah.example.com"],
        "purposes": ["server_auth"],
    }

    csr_info = create_csr_info(event)


def test_create_csr_subject(monkeypatch):
    monkeypatch.setenv("INTERNAL_S3_BUCKET", "s3://blah-int")
    monkeypatch.setenv("EXTERNAL_S3_BUCKET", "s3://blah")
    monkeypatch.setenv("ROOT_CA_INFO", "{}")
    monkeypatch.setenv("PUBLIC_CRL", "https://blah")
    monkeypatch.setenv("MAX_CERT_LIFETIME", "30")
    monkeypatch.setenv("ISSUING_CA_INFO", "{}")
    monkeypatch.setenv("ENVIRONMENT_NAME", "blah")
    monkeypatch.setenv("PROJECT", "blah")

    event = {
        "locality": "London",  # string, location
        "organization": "Acme Inc",  # string, organization name
        "organizational_unit": "Animation",  # string, organizational unit name
        "country": "GB",  # string, country code
    }

    subject = create_csr_subject(event)

    expected = "ST=England,OU=Gardening,O=Acme,L=London,1.2.840.113549.1.9.1=test@example.com,C=GB,CN=blah.example.com"
    assert subject.x509_name().rfc4514_string() == expected
