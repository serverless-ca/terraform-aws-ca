from cryptography.x509.oid import NameOID

from .crypto import CsrInfo, Subject


# test defaults
def test_csr_info_defaults():
    csr_info = CsrInfo("blah.example.com")

    assert csr_info.lifetime == 30
    assert csr_info.get_purposes() == ["client_auth"]
    assert csr_info.get_sans() == ["blah.example.com"]


def test_csr_info_with_sans():
    csr_info = CsrInfo("blah.example.com", sans=["foo.example.com"])

    assert csr_info.get_sans() == ["foo.example.com"]


# If an invalid SAN is supplied we ignore it
def test_csr_info_with_invalid_sans():
    csr_info = CsrInfo("blah.example.com", sans=["foo.example com"])

    assert csr_info.get_sans() == []


# if invalid and valid SANs are specified we filter out the invalid ones
def test_csr_info_with_invalid_and_valid_sans():
    csr_info = CsrInfo("blah.example.com", sans=["foo.example com", "bar.example.com"])

    assert csr_info.get_sans() == ["bar.example.com"]


def test_csr_info_with_purpose():
    csr_info = CsrInfo("blah.example.com", purposes=["server_auth"])

    assert csr_info.get_purposes() == ["server_auth"]


# If an invalid purpose is specified, we default to 'client_auth'
def test_csr_info_with_invalid_purpose():
    csr_info = CsrInfo("blah.example.com", purposes=["code_sign"])

    assert csr_info.get_purposes() == ["client_auth"]


# If valid and invalid purposes are specified, we filter out invalid/unsupported purposes
# and keep the valid / supported ones
def test_csr_info_with_invalid_and_valid_purposes():
    csr_info = CsrInfo("blah.example.com", purposes=["code_sign", "server_auth"])

    assert csr_info.get_purposes() == ["server_auth"]


def test_subject_x509_name_simple():
    subject = Subject("blah.example.com")

    x509_name = subject.x509_name()

    assert x509_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "blah.example.com"
    assert x509_name.rfc4514_string() == "CN=blah.example.com"


def test_subject_x509_name():
    subject = Subject("blah.example.com")
    subject.country = "GB"
    subject.email_address = "test@example.com"
    subject.locality = "London"
    subject.organization = "Acme"
    subject.organizational_unit = "Gardening"
    subject.state = "England"

    x509_name = subject.x509_name()

    assert x509_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "blah.example.com"
    assert x509_name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "GB"
    assert x509_name.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == "test@example.com"
    assert x509_name.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "London"
    assert x509_name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Acme"
    assert x509_name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Gardening"
    assert x509_name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "England"

    expected = "ST=England,OU=Gardening,O=Acme,L=London,1.2.840.113549.1.9.1=test@example.com,C=GB,CN=blah.example.com"
    assert x509_name.rfc4514_string() == expected


def test_subject_from_x509_name():
    subject = Subject("blah.example.com")
    subject.country = "GB"
    subject.email_address = "test@example.com"
    subject.locality = "London"
    subject.organization = "Acme"
    subject.organizational_unit = "Gardening"
    subject.state = "England"

    x509_name = subject.x509_name()

    new_subject = Subject.from_x509_subject(x509_name)

    assert subject.common_name == new_subject.common_name
    assert subject.country == new_subject.country
    assert subject.email_address == new_subject.email_address
    assert subject.locality == new_subject.locality
    assert subject.organization == new_subject.organization
    assert subject.organizational_unit == new_subject.organizational_unit
    assert subject.state == new_subject.state
