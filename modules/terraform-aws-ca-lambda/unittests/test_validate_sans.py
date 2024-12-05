from utils.certs.types import filter_and_validate_sans


def test_filter_and_validate_sans():
    input = ["example.com", "example.org", "example.net"]
    output = filter_and_validate_sans("example.com", input)
    expected = ["example.com", "example.org", "example.net"]

    assert output == expected


def test_filter_and_validate_sans_invalid_domain():
    input = ["example.com", "example.org", "net"]
    output = filter_and_validate_sans("example.com", input)
    expected = ["example.com", "example.org"]

    assert output == expected


def test_filter_and_validate_sans_wildcard_allowed():
    input = ["example.com", "example.org", "*.example.net"]
    output = filter_and_validate_sans("example.com", input)
    expected = ["example.com", "example.org", "*.example.net"]

    assert output == expected


def test_filter_and_validate_sans_wildcard_disallowed_if_base_domain_invalid():
    input = ["example.com", "example.org", "*.net"]
    output = filter_and_validate_sans("example.com", input)
    expected = ["example.com", "example.org"]

    assert output == expected
