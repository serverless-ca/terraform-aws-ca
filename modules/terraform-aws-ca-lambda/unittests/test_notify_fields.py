from lambda_code.tls_cert.tls_cert import Request


def test_request_notify_expiry_default():
    """notify_expiry defaults to None when not specified"""
    request = Request.from_dict({"common_name": "test.example.com"})
    assert request.notify_expiry is None


def test_request_notify_issued_default():
    """notify_issued defaults to None when not specified"""
    request = Request.from_dict({"common_name": "test.example.com"})
    assert request.notify_issued is None


def test_request_notify_expiry_true():
    """notify_expiry set to True"""
    request = Request.from_dict({"common_name": "test.example.com", "notify_expiry": True})
    assert request.notify_expiry is True


def test_request_notify_expiry_false():
    """notify_expiry set to False"""
    request = Request.from_dict({"common_name": "test.example.com", "notify_expiry": False})
    assert request.notify_expiry is False


def test_request_notify_issued_true():
    """notify_issued set to True"""
    request = Request.from_dict({"common_name": "test.example.com", "notify_issued": True})
    assert request.notify_issued is True


def test_request_notify_issued_false():
    """notify_issued set to False"""
    request = Request.from_dict({"common_name": "test.example.com", "notify_issued": False})
    assert request.notify_issued is False


def test_request_both_notify_fields():
    """Both notify fields set in a full request"""
    event = {
        "common_name": "smtp.test.fake.example-org.net",
        "country": "GB",
        "lifetime": 365,
        "locality": "Birmingham",
        "organization": "exampleorg",
        "organizational_unit": "Security Operations",
        "notify_expiry": True,
        "notify_issued": True,
        "base64_csr_data": "DELMAkGA1UEBhMCVUsxDzA==",
    }

    request = Request.from_dict(event)
    assert request.notify_expiry is True
    assert request.notify_issued is True
    assert request.common_name == "smtp.test.fake.example-org.net"
    assert request.lifetime == 365


def test_request_unknown_fields_ignored():
    """Unknown fields in event are silently ignored"""
    event = {
        "common_name": "test.example.com",
        "notify_expiry": True,
        "unknown_field": "should be ignored",
    }

    request = Request.from_dict(event)
    assert request.notify_expiry is True
    assert request.common_name == "test.example.com"
