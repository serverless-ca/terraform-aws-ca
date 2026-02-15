from utils.certs.types import (
    filter_and_validate_sans,
    filter_and_validate_sans_typed,
    normalize_sans_input,
    validate_dns_name,
    validate_ip_address,
    validate_email_address,
    validate_url,
    validate_dn,
)


# Legacy filter_and_validate_sans tests (backwards compatibility)
def test_filter_and_validate_sans():
    sans = ["example.com", "example.org", "example.net"]
    output = filter_and_validate_sans("example.com", sans)
    expected = ["example.com", "example.org", "example.net"]

    assert output == expected


def test_filter_and_validate_sans_invalid_domain():
    sans = ["example.com", "example.org", "net"]
    output = filter_and_validate_sans("example.com", sans)
    expected = ["example.com", "example.org"]

    assert output == expected


def test_filter_and_validate_sans_wildcard_allowed():
    sans = ["example.com", "example.org", "*.example.net"]
    output = filter_and_validate_sans("example.com", sans)
    expected = ["example.com", "example.org", "*.example.net"]

    assert output == expected


def test_filter_and_validate_sans_wildcard_disallowed_if_base_domain_invalid():
    sans = ["example.com", "example.org", "*.net"]
    output = filter_and_validate_sans("example.com", sans)
    expected = ["example.com", "example.org"]

    assert output == expected


def test_filter_and_validate_sans_mixed_domains():
    sans = ["example.com", "example.org", "*.example.net", "*.net", "Invalid DNS name"]
    output = filter_and_validate_sans("example.com", sans)
    expected = ["example.com", "example.org", "*.example.net"]

    assert output == expected


# Validation function tests
def test_validate_dns_name():
    assert validate_dns_name("example.com") is True
    assert validate_dns_name("*.example.com") is True
    assert validate_dns_name("sub.example.com") is True
    assert validate_dns_name("not a domain") is False
    assert validate_dns_name("*.net") is False


def test_validate_ip_address():
    assert validate_ip_address("192.168.1.1") is True
    assert validate_ip_address("10.0.0.1") is True
    assert validate_ip_address("2001:db8::1") is True
    assert validate_ip_address("::1") is True
    assert validate_ip_address("not-an-ip") is False
    assert validate_ip_address("256.1.1.1") is False


def test_validate_email_address():
    assert validate_email_address("user@example.com") is True
    assert validate_email_address("admin@test.org") is True
    assert validate_email_address("not-an-email") is False
    assert validate_email_address("missing@") is False


def test_validate_url():
    assert validate_url("https://example.com") is True
    assert validate_url("http://example.com/path") is True
    assert validate_url("not-a-url") is False


def test_validate_dn():
    assert validate_dn("CN=Example") is True
    assert validate_dn("CN=Example,O=Org,C=US") is True
    assert validate_dn("O=Org") is True
    assert validate_dn("not a dn") is False
    assert validate_dn("") is False


# Normalize SANs input tests
def test_normalize_sans_input_none():
    output = normalize_sans_input("example.com", None)
    assert output == [{"type": "DNS_NAME", "value": "example.com"}]


def test_normalize_sans_input_none_invalid_cn():
    output = normalize_sans_input("not a domain", None)
    assert output == []


def test_normalize_sans_input_string():
    output = normalize_sans_input("example.com", "www.example.com")
    assert output == [{"type": "DNS_NAME", "value": "www.example.com"}]


def test_normalize_sans_input_list_of_strings():
    output = normalize_sans_input("example.com", ["a.com", "b.com"])
    assert output == [
        {"type": "DNS_NAME", "value": "a.com"},
        {"type": "DNS_NAME", "value": "b.com"},
    ]


def test_normalize_sans_input_list_of_dicts():
    sans = [
        {"type": "DNS_NAME", "value": "example.com"},
        {"type": "IP_ADDRESS", "value": "192.168.1.1"},
    ]
    output = normalize_sans_input("example.com", sans)
    assert output == sans


def test_normalize_sans_input_map():
    sans = {
        "DNS_NAME": ["a.com", "b.com"],
        "IP_ADDRESS": "10.0.0.1",
    }
    output = normalize_sans_input("example.com", sans)
    assert len(output) == 3
    assert {"type": "DNS_NAME", "value": "a.com"} in output
    assert {"type": "DNS_NAME", "value": "b.com"} in output
    assert {"type": "IP_ADDRESS", "value": "10.0.0.1"} in output


# Typed SANs validation tests
def test_filter_and_validate_sans_typed_dns_only():
    sans = ["example.com", "example.org"]
    output = filter_and_validate_sans_typed("test.com", sans)
    assert output == [
        {"type": "DNS_NAME", "value": "example.com"},
        {"type": "DNS_NAME", "value": "example.org"},
    ]


def test_filter_and_validate_sans_typed_multiple_types():
    sans = [
        {"type": "DNS_NAME", "value": "example.com"},
        {"type": "IP_ADDRESS", "value": "192.168.1.1"},
        {"type": "EMAIL_ADDRESS", "value": "admin@example.com"},
    ]
    output = filter_and_validate_sans_typed("test.com", sans)
    assert len(output) == 3
    assert {"type": "DNS_NAME", "value": "example.com"} in output
    assert {"type": "IP_ADDRESS", "value": "192.168.1.1"} in output
    assert {"type": "EMAIL_ADDRESS", "value": "admin@example.com"} in output


def test_filter_and_validate_sans_typed_invalid_excluded():
    sans = [
        {"type": "DNS_NAME", "value": "valid.example.com"},
        {"type": "IP_ADDRESS", "value": "not-an-ip"},
        {"type": "EMAIL_ADDRESS", "value": "not-an-email"},
    ]
    output = filter_and_validate_sans_typed("test.com", sans)
    assert output == [{"type": "DNS_NAME", "value": "valid.example.com"}]


def test_filter_and_validate_sans_typed_invalid_type_excluded():
    sans = [
        {"type": "DNS_NAME", "value": "valid.example.com"},
        {"type": "INVALID_TYPE", "value": "something"},
    ]
    output = filter_and_validate_sans_typed("test.com", sans)
    assert output == [{"type": "DNS_NAME", "value": "valid.example.com"}]
