from cryptography.x509.oid import NameOID

from utils.certs.types import CsrInfo, Subject


# test defaults
def test_csr_info_defaults():
    csr_info = CsrInfo(Subject("blah.example.com"))

    assert csr_info.lifetime == 30
    assert csr_info.purposes == ["client_auth"]
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "blah.example.com"}]


def test_csr_info_with_sans():
    csr_info = CsrInfo(Subject("blah.example.com"), sans=["foo.example.com"])

    assert csr_info.sans == [{"type": "DNS_NAME", "value": "foo.example.com"}]


# If an invalid SAN is supplied we ignore it, but fall back to common name if it's valid
def test_csr_info_with_invalid_sans():
    csr_info = CsrInfo(Subject("blah.example.com"), sans=["foo.example com"])

    # Invalid SAN is excluded, but common name is used as fallback since it's a valid domain
    assert csr_info.sans == [{"type": "DNS_NAME", "value": "blah.example.com"}]


def test_csr_info_with_invalid_sans_and_invalid_cn():
    # When both SANs and common name are invalid, result is empty
    csr_info = CsrInfo(Subject("not a valid domain"), sans=["foo.example com"])

    assert not csr_info.sans


# if invalid and valid SANs are specified we filter out the invalid ones
def test_csr_info_with_invalid_and_valid_sans():
    csr_info = CsrInfo(Subject("blah.example.com"), sans=["foo.example com", "bar.example.com"])

    assert csr_info.sans == [{"type": "DNS_NAME", "value": "bar.example.com"}]


def test_csr_info_with_purpose():
    csr_info = CsrInfo(Subject("blah.example.com"), purposes=["server_auth"])

    assert csr_info.purposes == ["server_auth"]


# If an invalid purpose is specified, we default to 'client_auth'
def test_csr_info_with_invalid_purpose():
    csr_info = CsrInfo(Subject("blah.example.com"), purposes=["code_sign"])

    assert csr_info.purposes == ["client_auth"]


# If valid and invalid purposes are specified, we filter out invalid/unsupported purposes
# and keep the valid / supported ones
def test_csr_info_with_invalid_and_valid_purposes():
    csr_info = CsrInfo(Subject("blah.example.com"), purposes=["code_sign", "server_auth"])

    assert csr_info.purposes == ["server_auth"]


def test_csr_info_with_invalid_cn_and_no_san():
    csr_info = CsrInfo(Subject("not a valid dns name"))

    assert not csr_info.sans


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


# Extended Key Usage tests
def test_csr_info_with_extended_key_usages():
    csr_info = CsrInfo(Subject("blah.example.com"), extended_key_usages=["CODE_SIGNING", "EMAIL_PROTECTION"])

    assert csr_info.extended_key_usages == ["CODE_SIGNING", "EMAIL_PROTECTION"]


def test_csr_info_with_no_extended_key_usages():
    csr_info = CsrInfo(Subject("blah.example.com"))

    assert not csr_info.extended_key_usages


def test_csr_info_with_invalid_extended_key_usage():
    csr_info = CsrInfo(Subject("blah.example.com"), extended_key_usages=["INVALID_USAGE"])

    # Invalid extended key usages are filtered out
    assert not csr_info.extended_key_usages


def test_csr_info_with_mixed_valid_invalid_extended_key_usages():
    csr_info = CsrInfo(
        Subject("blah.example.com"), extended_key_usages=["CODE_SIGNING", "INVALID_USAGE", "TIME_STAMPING"]
    )

    # Only valid extended key usages are kept
    assert csr_info.extended_key_usages == ["CODE_SIGNING", "TIME_STAMPING"]


def test_csr_info_with_custom_oid_extended_key_usage():
    csr_info = CsrInfo(Subject("blah.example.com"), extended_key_usages=["1.3.6.1.5.5.7.3.17"])

    # Custom OIDs starting with 1. or 2. are allowed
    assert csr_info.extended_key_usages == ["1.3.6.1.5.5.7.3.17"]


def test_csr_info_with_all_valid_extended_key_usages():
    all_valid = [
        "TLS_WEB_SERVER_AUTHENTICATION",
        "TLS_WEB_CLIENT_AUTHENTICATION",
        "CODE_SIGNING",
        "EMAIL_PROTECTION",
        "TIME_STAMPING",
        "OCSP_SIGNING",
        "IPSEC_END_SYSTEM",
        "IPSEC_TUNNEL",
        "IPSEC_USER",
        "ANY",
    ]
    csr_info = CsrInfo(Subject("blah.example.com"), extended_key_usages=all_valid)

    assert csr_info.extended_key_usages == all_valid


def test_csr_info_with_none_extended_key_usage():
    # NONE is a valid value that means no additional extended key usages
    csr_info = CsrInfo(Subject("blah.example.com"), extended_key_usages=["NONE"])

    assert csr_info.extended_key_usages == ["NONE"]
