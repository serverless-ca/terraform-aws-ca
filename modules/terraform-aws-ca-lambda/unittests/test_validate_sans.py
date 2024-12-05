from utils.certs.types import filter_and_validate_sans


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
